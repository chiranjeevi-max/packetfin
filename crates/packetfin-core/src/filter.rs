//! Display-filter expressions.
//!
//! [`Filter::parse`] turns a display-filter expression into an AST and
//! [`Filter::matches`] evaluates it against a decoded [`Tree`]. The grammar
//! covers field and protocol existence, comparisons, `contains`, `matches`,
//! `in`, slices, the function calls `len`, `count`, `upper`, `lower`,
//! `string`, `hex`, `max`, `min` and `abs`, arithmetic, bitwise `&`, and
//! references to other fields.
//!
//! Operator semantics:
//! `==` is any-occurrence equality, `!=` is no-occurrence equality, `===` is
//! all-occurrence equality, `!==` is any-occurrence inequality, comparison
//! chains are conjoined pairwise, arithmetic result types follow the left
//! operand, and `matches` runs case-insensitive PCRE2 byte semantics. The
//! Rust `regex` crate lacks PCRE2's lookaround, backreferences, atomic and
//! possessive groups, `\K`, `\R`, `\X`, `\C` and Unicode property classes in
//! byte mode; those patterns are rejected here.

use std::cmp::Ordering;
use std::fmt;

use regex::bytes::{Regex, RegexBuilder};

use crate::fields::{self, FieldDef, FieldType, ProtocolDef};
use crate::tree::{Bytes, Field, Node, Tree, Value};

/// Deepest expression tree a filter may build.
///
/// The parser bounds parentheses, `not`, unary and function nesting; this
/// limit also bounds the left-deep tree a long operator chain builds, so
/// evaluation cannot overflow the stack on hostile input.
const MAX_EXPRESSION_DEPTH: usize = 128;

/// Longest regular expression pattern accepted, in bytes.
///
/// PCRE2 has its own compiled-size limit; this bound keeps hostile patterns
/// from making the Rust compiler allocate without limit.
const MAX_PATTERN_BYTES: usize = 4_096;

/// A parsed display filter.
#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    /// The parsed expression is boxed so the handle stays small in the
    /// command-line option structures that carry it.
    expr: Option<Box<Expr>>,
}

impl Filter {
    /// Parse a display-filter expression.
    ///
    /// An empty or whitespace-only expression matches every packet. A
    /// malformed field name or expression returns [`FilterError`] with the
    /// byte range that should be pointed at.
    pub fn parse(text: &str) -> Result<Self, FilterError> {
        if text.trim().is_empty() {
            return Ok(Self { expr: None });
        }
        let tokens = Lexer::new(text).lex()?;
        let mut parser = Parser::new(text, &tokens);
        let mut expr = parser.parse()?;
        if expression_depth(&expr) > MAX_EXPRESSION_DEPTH {
            return Err(FilterError::new(
                0,
                None,
                "the display filter is nested too deeply".to_string(),
            ));
        }
        resolve_expr(&mut expr)?;
        Ok(Self {
            expr: Some(Box::new(expr)),
        })
    }

    /// Whether the filter selects the packet represented by `tree`.
    pub fn matches(&self, tree: &Tree) -> bool {
        match &self.expr {
            Some(expr) => evaluate(expr, tree),
            None => true,
        }
    }

    /// Field and protocol definitions the expression reads.
    ///
    /// Callers that prune a decoded tree before evaluating the filter use
    /// this to keep the referenced occurrences and protocol nodes. The lists
    /// may contain duplicates; selections ignore them.
    pub fn references(&self) -> (Vec<&'static FieldDef>, Vec<&'static ProtocolDef>) {
        let mut fields = Vec::new();
        let mut protocols = Vec::new();
        let Some(root) = &self.expr else {
            return (fields, protocols);
        };
        let mut pending = vec![NodeRef::Expr(root)];
        while let Some(reference) = pending.pop() {
            match reference {
                NodeRef::Expr(expr) => match expr {
                    Expr::Protocol { protocol, .. } => protocols.push(*protocol),
                    Expr::Field { field, layer } => {
                        fields.push(*field);
                        if layer.is_some()
                            && let Some(protocol) = protocol_by_name(field.parent)
                        {
                            protocols.push(protocol);
                        }
                    }
                    Expr::Truthy(operand) => pending.push(NodeRef::Operand(operand)),
                    Expr::Not(inner) => pending.push(NodeRef::Expr(inner)),
                    Expr::And(left, right) | Expr::Or(left, right) | Expr::Xor(left, right) => {
                        pending.push(NodeRef::Expr(left));
                        pending.push(NodeRef::Expr(right));
                    }
                    Expr::Compare { left, right, .. } | Expr::Contains { left, right } => {
                        pending.push(NodeRef::Operand(left));
                        pending.push(NodeRef::Operand(right));
                    }
                    Expr::Matches { left, .. } => pending.push(NodeRef::Operand(left)),
                    Expr::In {
                        field,
                        layer,
                        members,
                    } => {
                        fields.push(*field);
                        if layer.is_some()
                            && let Some(protocol) = protocol_by_name(field.parent)
                        {
                            protocols.push(protocol);
                        }
                        for member in members {
                            match member {
                                InMember::Value(operand) => pending.push(NodeRef::Operand(operand)),
                                InMember::Range(start, end) => {
                                    pending.push(NodeRef::Operand(start));
                                    pending.push(NodeRef::Operand(end));
                                }
                                InMember::Cidr { .. } => {}
                            }
                        }
                    }
                },
                NodeRef::Operand(operand) => match &operand.kind {
                    OperandKind::Field { field, layer, .. } => {
                        fields.push(*field);
                        if layer.is_some()
                            && let Some(protocol) = protocol_by_name(field.parent)
                        {
                            protocols.push(protocol);
                        }
                    }
                    OperandKind::Protocol { protocol, .. } => protocols.push(*protocol),
                    OperandKind::Slice { inner, .. }
                    | OperandKind::Negate(inner)
                    | OperandKind::UnaryPlus(inner) => {
                        pending.push(NodeRef::Operand(inner));
                    }
                    OperandKind::Function { function, arg, .. } => {
                        if matches!(function, Function::Len)
                            && matches!(arg.kind, OperandKind::Protocol { .. })
                        {
                            fields.extend(fields::registry().fields().iter().copied());
                        }
                        pending.push(NodeRef::Operand(arg));
                    }
                    OperandKind::Binary { left, right, .. } => {
                        pending.push(NodeRef::Operand(left));
                        pending.push(NodeRef::Operand(right));
                    }
                    OperandKind::TokenLiteral(_) | OperandKind::Literal { .. } => {}
                },
            }
        }
        (fields, protocols)
    }
}

enum NodeRef<'a> {
    Expr(&'a Expr),
    Operand(&'a Operand),
}

/// Why a display filter could not be parsed.
///
/// `offset` is a byte position in the original expression. `length` is the
/// number of bytes the diagnostic should underline; `None` means the problem
/// is at the end of the expression and there is nothing to underline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterError {
    offset: usize,
    length: Option<usize>,
    message: String,
}

impl FilterError {
    fn new(offset: usize, length: Option<usize>, message: String) -> Self {
        Self {
            offset,
            length,
            message,
        }
    }

    fn at(token: &Token, message: impl Into<String>) -> Self {
        let length = token
            .end
            .checked_sub(token.start)
            .filter(|length| *length > 0);
        Self::new(token.start, length, message.into())
    }

    fn at_end(offset: usize, message: impl Into<String>) -> Self {
        Self::new(offset, None, message.into())
    }

    fn at_span(start: usize, end: usize, message: impl Into<String>) -> Self {
        let length = end.checked_sub(start).filter(|length| *length > 0);
        Self::new(start, length, message.into())
    }

    /// Byte offset of the problem in the expression.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Number of bytes to underline, or `None` at end of input.
    pub fn length(&self) -> Option<usize> {
        self.length
    }

    /// Human-readable explanation, without a program-name prefix.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FilterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FilterError {}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Protocol {
        protocol: &'static ProtocolDef,
        layer: Option<u64>,
    },
    Field {
        field: &'static FieldDef,
        layer: Option<u64>,
    },
    Truthy(Operand),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Compare {
        left: Operand,
        operator: CompareOp,
        right: Operand,
    },
    Contains {
        left: Operand,
        right: Operand,
    },
    Matches {
        left: Operand,
        pattern: Pattern,
    },
    In {
        field: &'static FieldDef,
        layer: Option<u64>,
        members: Vec<InMember>,
    },
}

#[derive(Clone, Debug, PartialEq)]
enum OperandKind {
    Field {
        field: &'static FieldDef,
        layer: Option<u64>,
    },
    Protocol {
        protocol: &'static ProtocolDef,
        layer: Option<u64>,
    },
    Slice {
        inner: Box<Operand>,
        slice: Slice,
    },
    TokenLiteral(TokenLiteral),
    Literal {
        literal: Literal,
        ty: Type,
    },
    Function {
        function: Function,
        arg: Box<Operand>,
        ty: Type,
    },
    Negate(Box<Operand>),
    UnaryPlus(Box<Operand>),
    Binary {
        operator: ArithOp,
        left: Box<Operand>,
        right: Box<Operand>,
        ty: Type,
    },
}

#[derive(Clone, Debug, PartialEq)]
struct Operand {
    kind: OperandKind,
    start: usize,
    end: usize,
}

impl Operand {
    fn new(kind: OperandKind, start: usize, end: usize) -> Self {
        Self { kind, start, end }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenLiteral {
    Word(String),
    Quoted(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Type {
    Uint(u32),
    Int(u32),
    Double,
    Boolean,
    String,
    Bytes,
    Ethernet,
    Eui64,
    Ipv4,
    Ipv6,
    Time,
    Relative,
    Protocol,
    Untyped,
}

impl Type {
    fn field_type(self) -> Option<FieldType> {
        match self {
            Self::Uint(8) => Some(FieldType::Uint8),
            Self::Uint(16) => Some(FieldType::Uint16),
            Self::Uint(24) => Some(FieldType::Uint24),
            Self::Uint(32) => Some(FieldType::Uint32),
            Self::Uint(64) => Some(FieldType::Uint64),
            Self::Relative => Some(FieldType::RelativeTime),
            Self::Int(8) => Some(FieldType::Int8),
            Self::Int(16) => Some(FieldType::Int16),
            Self::Int(32) => Some(FieldType::Int32),
            Self::Int(64) => Some(FieldType::Int64),
            Self::Double => Some(FieldType::Double),
            _ => None,
        }
    }

    fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::Uint(_) | Self::Int(_) | Self::Double | Self::Relative
        )
    }

    fn is_sequence(self) -> bool {
        matches!(
            self,
            Self::String
                | Self::Bytes
                | Self::Ethernet
                | Self::Eui64
                | Self::Ipv4
                | Self::Ipv6
                | Self::Protocol
        )
    }

    fn name(self) -> String {
        match self {
            Self::Uint(bits) => format!("unsigned {bits}-bit integer"),
            Self::Int(bits) => format!("signed {bits}-bit integer"),
            Self::Double => "double".to_string(),
            Self::Boolean => "boolean".to_string(),
            Self::String => "string".to_string(),
            Self::Bytes => "byte sequence".to_string(),
            Self::Ethernet => "Ethernet address".to_string(),
            Self::Eui64 => "EUI-64 address".to_string(),
            Self::Ipv4 => "IPv4 address".to_string(),
            Self::Ipv6 => "IPv6 address".to_string(),
            Self::Time => "date and time".to_string(),
            Self::Relative => "relative time".to_string(),
            Self::Protocol => "protocol".to_string(),
            Self::Untyped => "value".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Literal {
    Integer(i128),
    Double(f64),
    Boolean(bool),
    String(String),
    Bytes(Bytes),
    Ethernet([u8; 6]),
    Eui64([u8; 8]),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Time { seconds: i64, nanos: u32 },
}

#[derive(Clone, Debug)]
struct Pattern {
    source: String,
    regex: Regex,
}

impl Eq for Pattern {}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompareOp {
    AnyEq,
    AllEq,
    AnyNe,
    AllNe,
    AnyLt,
    AnyGt,
    AnyLe,
    AnyGe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArithOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    BitwiseAnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Function {
    Len,
    Count,
    Upper,
    Lower,
    String,
    Hex,
    Max,
    Min,
    Abs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slice {
    start: Option<i64>,
    length: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
enum InMember {
    Value(Operand),
    Range(Operand, Operand),
    Cidr { network: Literal, prefix: u8 },
}

impl Literal {
    fn ty(&self) -> Type {
        match self {
            Self::Integer(value) => {
                if *value < 0 {
                    Type::Int(64)
                } else {
                    Type::Uint(64)
                }
            }
            Self::Double(_) => Type::Double,
            Self::Boolean(_) => Type::Boolean,
            Self::String(_) => Type::String,
            Self::Bytes(_) => Type::Bytes,
            Self::Ethernet(_) => Type::Ethernet,
            Self::Eui64(_) => Type::Eui64,
            Self::Ipv4(_) => Type::Ipv4,
            Self::Ipv6(_) => Type::Ipv6,
            Self::Time { .. } => Type::Time,
        }
    }
}

fn type_of(field_type: FieldType) -> Type {
    match field_type {
        FieldType::Uint8 => Type::Uint(8),
        FieldType::Uint16 => Type::Uint(16),
        FieldType::Uint24 => Type::Uint(24),
        FieldType::Uint32 | FieldType::FrameNumber => Type::Uint(32),
        FieldType::Uint64 => Type::Uint(64),
        FieldType::Int8 => Type::Int(8),
        FieldType::Int16 => Type::Int(16),
        FieldType::Int32 => Type::Int(32),
        FieldType::Int64 => Type::Int(64),
        FieldType::Boolean => Type::Boolean,
        FieldType::Ethernet => Type::Ethernet,
        FieldType::Eui64 => Type::Eui64,
        FieldType::Ipv4 => Type::Ipv4,
        FieldType::Ipv6 => Type::Ipv6,
        FieldType::String | FieldType::StringZ | FieldType::StringzPad | FieldType::Oid => {
            Type::String
        }
        FieldType::Double => Type::Double,
        FieldType::Bytes => Type::Bytes,
        FieldType::None => Type::Untyped,
        FieldType::AbsoluteTime => Type::Time,
        // Relative times are stored as nanoseconds and compare numerically;
        // the operand parser scales fractional seconds to the same unit.
        FieldType::RelativeTime => Type::Relative,
    }
}

fn slice_type(inner: Type) -> Type {
    match inner {
        Type::String => Type::String,
        _ => Type::Bytes,
    }
}

fn compatible(left: Type, right: Type) -> bool {
    if left == right {
        return true;
    }
    matches!(
        (left, right),
        (Type::Uint(_) | Type::Int(_), Type::Uint(_) | Type::Int(_))
            | (Type::Bytes, Type::Ethernet | Type::Eui64)
            | (Type::Ethernet | Type::Eui64, Type::Bytes)
    )
}

fn protocol_by_name(name: &str) -> Option<&'static ProtocolDef> {
    fields::protocols()
        .iter()
        .copied()
        .find(|protocol| protocol.filter_name == name)
}

fn function_by_name(name: &str) -> Option<Function> {
    match name {
        "len" => Some(Function::Len),
        "count" => Some(Function::Count),
        "upper" => Some(Function::Upper),
        "lower" => Some(Function::Lower),
        "string" => Some(Function::String),
        "hex" => Some(Function::Hex),
        "max" => Some(Function::Max),
        "min" => Some(Function::Min),
        "abs" => Some(Function::Abs),
        _ => None,
    }
}

fn comparison_operator(kind: &Kind) -> Option<CompareOp> {
    match kind {
        Kind::Eq => Some(CompareOp::AnyEq),
        Kind::AllEq => Some(CompareOp::AllEq),
        Kind::Ne => Some(CompareOp::AllNe),
        Kind::AnyNe => Some(CompareOp::AnyNe),
        Kind::Lt => Some(CompareOp::AnyLt),
        Kind::Gt => Some(CompareOp::AnyGt),
        Kind::Le => Some(CompareOp::AnyLe),
        Kind::Ge => Some(CompareOp::AnyGe),
        Kind::Word(word) => match word.as_str() {
            "eq" | "any_eq" => Some(CompareOp::AnyEq),
            "all_eq" => Some(CompareOp::AllEq),
            "ne" | "all_ne" => Some(CompareOp::AllNe),
            "any_ne" => Some(CompareOp::AnyNe),
            "lt" => Some(CompareOp::AnyLt),
            "gt" => Some(CompareOp::AnyGt),
            "le" => Some(CompareOp::AnyLe),
            "ge" => Some(CompareOp::AnyGe),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Type resolution
// ---------------------------------------------------------------------------

fn resolve_expr(expr: &mut Expr) -> Result<(), FilterError> {
    match expr {
        Expr::Protocol { .. } | Expr::Field { .. } => Ok(()),
        Expr::Truthy(operand) => {
            let start = operand.start;
            let end = operand.end;
            resolve_operand(operand, None)?;
            if !has_field(operand) {
                return Err(constant_error(start, end));
            }
            Ok(())
        }
        Expr::Not(inner) => resolve_expr(inner),
        Expr::And(left, right) | Expr::Or(left, right) | Expr::Xor(left, right) => {
            resolve_expr(left)?;
            resolve_expr(right)
        }
        Expr::Compare {
            left,
            operator,
            right,
        } => resolve_comparison(left, *operator, right),
        Expr::Contains { left, right } => resolve_contains(left, right),
        Expr::Matches { left, .. } => {
            let ty = resolve_operand(left, None)?;
            if !matches!(
                ty,
                Type::String | Type::Bytes | Type::Ethernet | Type::Eui64
            ) {
                return Err(FilterError::at_span(
                    left.start,
                    left.end,
                    format!("{} cannot participate in a matches comparison", ty.name()),
                ));
            }
            Ok(())
        }
        Expr::In { field, members, .. } => {
            let field_type = type_of(field.field_type);
            let mut resolved = Vec::with_capacity(members.len());
            for member in members.iter_mut() {
                resolved.push(resolve_member(member, field_type)?);
            }
            *members = resolved;
            Ok(())
        }
    }
}

fn resolve_member(member: &mut InMember, field_type: Type) -> Result<InMember, FilterError> {
    match member {
        InMember::Value(operand) => {
            let ty = resolve_operand(operand, Some(field_type))?;
            if ty == Type::Untyped {
                return Err(constant_error(operand.start, operand.end));
            }
            if !compatible(field_type, ty) {
                return Err(FilterError::at_span(
                    operand.start,
                    operand.end,
                    format!(
                        "{} and {} are not of compatible types",
                        field_type.name(),
                        ty.name()
                    ),
                ));
            }
            Ok(InMember::Value(operand.clone()))
        }
        InMember::Range(start, end) => {
            let start_ty = resolve_operand(start, Some(field_type))?;
            let end_ty = resolve_operand(end, Some(field_type))?;
            for (ty, operand) in [(start_ty, &*start), (end_ty, &*end)] {
                if ty == Type::Untyped {
                    return Err(constant_error(operand.start, operand.end));
                }
                if !compatible(field_type, ty) {
                    return Err(FilterError::at_span(
                        operand.start,
                        operand.end,
                        format!(
                            "{} and {} are not of compatible types",
                            field_type.name(),
                            ty.name()
                        ),
                    ));
                }
            }
            Ok(InMember::Range(start.clone(), end.clone()))
        }
        InMember::Cidr { network, prefix } => Ok(InMember::Cidr {
            network: network.clone(),
            prefix: *prefix,
        }),
    }
}

fn reject_label(operand: &Operand) -> Result<(), FilterError> {
    if let OperandKind::Field { field, .. } = &operand.kind
        && field.field_type == FieldType::None
    {
        return Err(FilterError::at_span(
            operand.start,
            operand.end,
            format!("{} is a label and cannot be compared", field.abbrev),
        ));
    }
    Ok(())
}

fn has_unconverted(operand: &Operand) -> bool {
    match &operand.kind {
        OperandKind::TokenLiteral(_) => true,
        OperandKind::Slice { inner, .. }
        | OperandKind::Negate(inner)
        | OperandKind::UnaryPlus(inner) => has_unconverted(inner),
        OperandKind::Function { arg, .. } => has_unconverted(arg),
        OperandKind::Binary { left, right, .. } => has_unconverted(left) || has_unconverted(right),
        OperandKind::Field { .. } | OperandKind::Protocol { .. } | OperandKind::Literal { .. } => {
            false
        }
    }
}

fn has_field(operand: &Operand) -> bool {
    match &operand.kind {
        OperandKind::Field { .. } | OperandKind::Protocol { .. } => true,
        OperandKind::Slice { inner, .. }
        | OperandKind::Negate(inner)
        | OperandKind::UnaryPlus(inner) => has_field(inner),
        OperandKind::Function { arg, .. } => has_field(arg),
        OperandKind::Binary { left, right, .. } => has_field(left) || has_field(right),
        OperandKind::TokenLiteral(_) | OperandKind::Literal { .. } => false,
    }
}

fn constant_error(start: usize, end: usize) -> FilterError {
    FilterError::at_span(start, end, "constant expression is invalid".to_string())
}

fn resolve_comparison(
    left: &mut Operand,
    operator: CompareOp,
    right: &mut Operand,
) -> Result<(), FilterError> {
    reject_label(left)?;
    reject_label(right)?;
    if !has_field(left) && !has_field(right) {
        return Err(constant_error(left.start, right.end.max(left.end)));
    }
    let left_type = resolve_operand(left, None)?;
    let right_type = resolve_operand(right, None)?;
    let (left_type, right_type) = match (left_type, right_type) {
        (Type::Untyped, Type::Untyped) => {
            return Err(constant_error(left.start, right.end.max(left.end)));
        }
        (Type::Untyped, right_type) => {
            resolve_operand(left, Some(right_type))?;
            (right_type, right_type)
        }
        (left_type, Type::Untyped) => {
            resolve_operand(right, Some(left_type))?;
            (left_type, left_type)
        }
        (left_type, right_type) => (left_type, right_type),
    };
    if !compatible(left_type, right_type) {
        return Err(FilterError::at_span(
            right.start,
            right.end,
            format!(
                "{} and {} are not of compatible types",
                left_type.name(),
                right_type.name()
            ),
        ));
    }
    validate_literal(left, right_type)?;
    validate_literal(right, left_type)?;
    let _ = operator;
    Ok(())
}

fn validate_literal(operand: &Operand, expected: Type) -> Result<(), FilterError> {
    let OperandKind::Literal {
        literal: Literal::Integer(value),
        ..
    } = &operand.kind
    else {
        return Ok(());
    };
    let Some((minimum, maximum)) = integer_range(expected) else {
        return Ok(());
    };
    if expected.is_numeric() && (*value < minimum || *value > maximum) {
        return Err(FilterError::at_span(
            operand.start,
            operand.end,
            format!("{value} does not fit this {}", expected.name()),
        ));
    }
    Ok(())
}

fn integer_range(ty: Type) -> Option<(i128, i128)> {
    match ty {
        Type::Uint(bits) => {
            let maximum = (1_i128 << bits.min(127)) - 1;
            Some((-maximum, maximum))
        }
        Type::Int(bits) => {
            let maximum = (1_i128 << (bits.min(127) - 1)) - 1;
            Some((-maximum - 1, maximum))
        }
        _ => None,
    }
}

fn resolve_contains(left: &mut Operand, right: &mut Operand) -> Result<(), FilterError> {
    reject_label(left)?;
    reject_label(right)?;
    if matches!(right.kind, OperandKind::UnaryPlus(_)) {
        return Err(FilterError::at_span(
            right.start,
            right.end,
            "\"+\" is not valid in a contains operand".to_string(),
        ));
    }
    let left_type = resolve_operand(left, None)?;
    if !matches!(
        left_type,
        Type::String | Type::Bytes | Type::Ethernet | Type::Eui64
    ) {
        return Err(FilterError::at_span(
            left.start,
            left.end,
            format!(
                "{} cannot participate in a contains comparison",
                left_type.name()
            ),
        ));
    }
    if matches!(left_type, Type::Ethernet | Type::Eui64)
        && let OperandKind::TokenLiteral(token) = &right.kind
    {
        let literal = match token {
            TokenLiteral::Quoted(_) => {
                return Err(FilterError::at_span(
                    right.start,
                    right.end,
                    format!(
                        "{} cannot be converted from a quoted string",
                        left_type.name()
                    ),
                ));
            }
            TokenLiteral::Word(text) => {
                let token = Token {
                    kind: Kind::Word(text.clone()),
                    start: right.start,
                    end: right.end,
                };
                let bytes = if left_type == Type::Ethernet {
                    ethernet_needle(text, &token)?
                } else {
                    eui64_needle(text, &token)?
                };
                Literal::Bytes(bytes.into())
            }
        };
        right.kind = OperandKind::Literal {
            literal,
            ty: Type::Bytes,
        };
    }
    let resolve_type = match left_type {
        Type::String => Type::String,
        _ => Type::Bytes,
    };
    let right_type = resolve_operand(right, Some(resolve_type))?;
    if right_type == Type::Untyped {
        return Err(constant_error(right.start, right.end));
    }
    if !compatible(left_type, right_type) && !compatible(resolve_type, right_type) {
        return Err(FilterError::at_span(
            right.start,
            right.end,
            format!(
                "{} and {} are not of compatible types",
                left_type.name(),
                right_type.name()
            ),
        ));
    }
    Ok(())
}

fn resolve_operand(operand: &mut Operand, expected: Option<Type>) -> Result<Type, FilterError> {
    // A relative time stores nanoseconds (see `FieldType::RelativeTime`), but
    // the evaluator reads a bare constant beside one as seconds. Arithmetic
    // made only of constants takes its unit from that enclosing context, so
    // evaluate it here and store the scaled value: otherwise `1 * 1` would
    // reach evaluation as one nanosecond and `10 / 4` as integer two.
    if expected == Some(Type::Relative)
        && matches!(&operand.kind, OperandKind::Binary { .. })
        && let Some(nanos) = relative_constant_nanos(operand)?
    {
        operand.kind = OperandKind::Literal {
            literal: Literal::Integer(nanos),
            ty: Type::Relative,
        };
        return Ok(Type::Relative);
    }
    match &mut operand.kind {
        OperandKind::Field { field, .. } => Ok(type_of(field.field_type)),
        OperandKind::Protocol { .. } => Ok(Type::Protocol),
        OperandKind::Slice { inner, .. } => {
            let inner_type = resolve_operand(inner, None)?;
            if inner_type == Type::Untyped {
                return Ok(Type::Untyped);
            }
            // A protocol slice would read the protocol's own frame bytes, and
            // the evaluator keeps no byte source for a protocol node. Reject
            // it here so the deviation is a parse error instead of a filter
            // that silently matches nothing.
            if inner_type == Type::Protocol {
                return Err(FilterError::at_span(
                    inner.start,
                    inner.end,
                    format!(
                        "{} cannot be sliced into a sequence of bytes",
                        inner_type.name()
                    ),
                ));
            }
            if !inner_type.is_sequence() {
                return Err(FilterError::at_span(
                    inner.start,
                    inner.end,
                    format!(
                        "{} cannot be sliced into a sequence of bytes",
                        inner_type.name()
                    ),
                ));
            }
            Ok(slice_type(inner_type))
        }
        OperandKind::TokenLiteral(token) => {
            let Some(expected) = expected.filter(|ty| *ty != Type::Untyped) else {
                return Ok(Type::Untyped);
            };
            let literal_token = match token {
                TokenLiteral::Word(text) => Token {
                    kind: Kind::Word(text.clone()),
                    start: operand.start,
                    end: operand.end,
                },
                TokenLiteral::Quoted(bytes) => Token {
                    kind: Kind::Quoted(bytes.clone()),
                    start: operand.start,
                    end: operand.end,
                },
            };
            let literal = match token {
                TokenLiteral::Word(text) => convert_word(expected, text, &literal_token)?,
                TokenLiteral::Quoted(bytes) => convert_quoted(expected, bytes, &literal_token)?,
            };
            let ty = match &literal {
                Literal::Integer(value) if *value < 0 => Type::Int(64),
                _ => expected,
            };
            operand.kind = OperandKind::Literal { literal, ty };
            Ok(ty)
        }
        OperandKind::Literal { ty, .. } => Ok(*ty),
        OperandKind::Function { function, arg, ty } => {
            let function = *function;
            resolve_function(function, arg, ty, operand.start, operand.end)
        }
        OperandKind::Negate(inner) => {
            let ty = resolve_operand(inner, expected)?;
            if let OperandKind::Literal {
                literal: Literal::Integer(value),
                ..
            } = &inner.kind
                && let Some(value) = value.checked_neg()
            {
                let ty = if value < 0 {
                    Type::Int(64)
                } else {
                    Type::Uint(64)
                };
                operand.kind = OperandKind::Literal {
                    literal: Literal::Integer(value),
                    ty,
                };
                return Ok(ty);
            }
            if ty == Type::Untyped {
                return Ok(Type::Untyped);
            }
            if !ty.is_numeric() && ty != Type::Time {
                return Err(FilterError::at_span(
                    inner.start,
                    inner.end,
                    "argument cannot be negated".to_string(),
                ));
            }
            Ok(if ty == Type::Time {
                Type::Time
            } else {
                Type::Int(64)
            })
        }
        OperandKind::UnaryPlus(inner) => resolve_operand(inner, expected),
        OperandKind::Binary {
            operator,
            left,
            right,
            ty,
        } => {
            let operator = *operator;
            resolve_binary(
                operator,
                left,
                right,
                ty,
                expected,
                operand.start,
                operand.end,
            )
        }
    }
}

fn resolve_binary(
    operator: ArithOp,
    left: &mut Operand,
    right: &mut Operand,
    ty: &mut Type,
    expected: Option<Type>,
    start: usize,
    end: usize,
) -> Result<Type, FilterError> {
    let left_type = resolve_operand(left, None)?;
    let right_type = resolve_operand(right, None)?;
    let target = match (left_type, right_type) {
        (Type::Untyped, Type::Untyped) => expected.unwrap_or(Type::Untyped),
        (Type::Untyped, Type::Int(_))
            if matches!(
                operator,
                ArithOp::Add | ArithOp::Subtract | ArithOp::Multiply
            ) =>
        {
            negated_unsigned_type(right).unwrap_or(Type::Uint(16))
        }
        (Type::Untyped, right_type) => right_type,
        (left_type, _) => left_type,
    };
    if target == Type::Untyped {
        *ty = Type::Untyped;
        return Ok(Type::Untyped);
    }
    // A relative time is stored in nanoseconds like an absolute time, but a
    // bare scalar beside `*` or `/` counts seconds rather than nanoseconds:
    // the scalar scales the value, it is not itself a duration.
    let time = matches!(target, Type::Time | Type::Relative);
    if time {
        if matches!(operator, ArithOp::Modulo | ArithOp::BitwiseAnd) {
            return Err(FilterError::at_span(
                start,
                end,
                format!(
                    "\"{}\" is not a valid arithmetic operator for {}",
                    arith_symbol(operator),
                    target.name()
                ),
            ));
        }
        // A relative time combined with an absolute time is a scalar
        // duration in seconds (RFC 3339 timestamps are offsets from an
        // epoch): the sum or difference stays numeric, as the reference
        // implementation evaluates it. Multiplication and division by an
        // absolute time has no meaning and is rejected at parse time.
        let mixed_absolute =
            target == Type::Relative && (left_type == Type::Time || right_type == Type::Time);
        // A time operand combines with a number (or another time); anything
        // else, such as an address, cannot be converted and would otherwise
        // resolve and then silently match nothing.
        for (operand, ty) in [(&*left, left_type), (&*right, right_type)] {
            if ty != Type::Untyped
                && !matches!(
                    ty,
                    Type::Uint(_) | Type::Int(_) | Type::Double | Type::Time | Type::Relative
                )
            {
                return Err(FilterError::at_span(
                    operand.start,
                    operand.end,
                    format!(
                        "{} cannot be used with {}",
                        ty.name(),
                        arith_symbol(operator)
                    ),
                ));
            }
        }
        if mixed_absolute {
            if matches!(operator, ArithOp::Multiply | ArithOp::Divide) {
                return Err(FilterError::at_span(
                    right.start,
                    right.end,
                    format!(
                        "{} cannot be the right-hand operand of {}",
                        Type::Time.name(),
                        arith_symbol(operator)
                    ),
                ));
            }
            if has_unconverted(left) {
                resolve_operand(left, Some(Type::Relative))?;
            }
            if has_unconverted(right) {
                resolve_operand(right, Some(Type::Relative))?;
            }
            *ty = Type::Double;
            return Ok(Type::Double);
        }
        let operand_type = match operator {
            ArithOp::Multiply | ArithOp::Divide => Type::Int(64),
            _ => target,
        };
        if has_unconverted(left) {
            resolve_operand(left, Some(operand_type))?;
        }
        if has_unconverted(right) {
            resolve_operand(right, Some(operand_type))?;
        }
    } else {
        if !target.is_numeric() {
            return Err(FilterError::at_span(
                start,
                end,
                format!(
                    "{} cannot be combined with {}",
                    target.name(),
                    arith_symbol(operator)
                ),
            ));
        }
        if has_unconverted(left) {
            resolve_operand(left, Some(target))?;
        }
        let resolved_right = if has_unconverted(right) {
            resolve_operand(right, Some(target))?
        } else {
            right_type
        };
        if resolved_right != Type::Untyped && !resolved_right.is_numeric() {
            return Err(FilterError::at_span(
                right.start,
                right.end,
                format!(
                    "{} cannot be used with {}",
                    resolved_right.name(),
                    arith_symbol(operator)
                ),
            ));
        }
    }
    *ty = target;
    Ok(target)
}

/// Nanoseconds per second, the unit a relative field stores.
const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// Evaluate a constant relative-time expression as exact nanoseconds.
///
/// A relative field keeps nanoseconds, while a bare constant beside one counts
/// seconds: `frame.time_relative + 10 / 4` adds 2.5 s. A node whose operands
/// are all constants has no unit of its own, so its enclosing relative context
/// supplies one, and the node is folded here. Every operation stays in integer
/// nanoseconds with checked arithmetic; routing the value through `f64` would
/// lose the low nanoseconds of a large relative time.
///
/// Returns `Ok(None)` for an operand that is not a constant expression so the
/// ordinary resolution path and its diagnostics still apply.
fn relative_constant_nanos(operand: &Operand) -> Result<Option<i128>, FilterError> {
    match &operand.kind {
        OperandKind::TokenLiteral(TokenLiteral::Word(text)) => {
            if let Some(seconds) = parse_integer(text) {
                return seconds
                    .checked_mul(NANOS_PER_SECOND)
                    .map(Some)
                    .ok_or_else(|| relative_constant_range(operand));
            }
            Ok(parse_relative_seconds(text))
        }
        OperandKind::Literal { literal, ty } => match (literal, *ty) {
            (Literal::Integer(value), Type::Relative) => Ok(Some(*value)),
            (Literal::Integer(value), Type::Uint(_) | Type::Int(_)) => value
                .checked_mul(NANOS_PER_SECOND)
                .map(Some)
                .ok_or_else(|| relative_constant_range(operand)),
            _ => Ok(None),
        },
        OperandKind::UnaryPlus(inner) => relative_constant_nanos(inner),
        OperandKind::Negate(inner) => {
            let Some(value) = relative_constant_nanos(inner)? else {
                return Ok(None);
            };
            value
                .checked_neg()
                .map(Some)
                .ok_or_else(|| relative_constant_range(operand))
        }
        OperandKind::Binary {
            operator,
            left,
            right,
            ..
        } => {
            let Some(left) = relative_constant_nanos(left)? else {
                return Ok(None);
            };
            let Some(right) = relative_constant_nanos(right)? else {
                return Ok(None);
            };
            let value = match operator {
                ArithOp::Add => left.checked_add(right),
                ArithOp::Subtract => left.checked_sub(right),
                ArithOp::Multiply => left
                    .checked_mul(right)
                    .and_then(|product| rounded_quotient(product, NANOS_PER_SECOND)),
                ArithOp::Divide if right == 0 => {
                    return Err(FilterError::at_span(
                        operand.start,
                        operand.end,
                        "division by zero".to_string(),
                    ));
                }
                ArithOp::Divide => left
                    .checked_mul(NANOS_PER_SECOND)
                    .and_then(|scaled| rounded_quotient(scaled, right)),
                ArithOp::Modulo | ArithOp::BitwiseAnd => {
                    return Err(FilterError::at_span(
                        operand.start,
                        operand.end,
                        format!(
                            "\"{}\" is not a valid arithmetic operator for {}",
                            arith_symbol(*operator),
                            Type::Relative.name()
                        ),
                    ));
                }
            };
            value
                .map(Some)
                .ok_or_else(|| relative_constant_range(operand))
        }
        _ => Ok(None),
    }
}

/// The diagnostic for a relative constant that does not fit `i128` nanoseconds.
fn relative_constant_range(operand: &Operand) -> FilterError {
    FilterError::at_span(
        operand.start,
        operand.end,
        "relative time constant is out of range".to_string(),
    )
}

/// Divide with the quotient rounded to nearest, ties away from zero.
///
/// Folding multiplies and divides durations, so the fractional nanosecond is
/// rounded once here instead of being truncated (`1 / 3` is 333333333 ns).
fn rounded_quotient(numerator: i128, denominator: i128) -> Option<i128> {
    let quotient = numerator.checked_div(denominator)?;
    let remainder = numerator.checked_rem(denominator)?;
    if remainder == 0 {
        return Some(quotient);
    }
    let doubled = remainder.unsigned_abs().checked_mul(2)?;
    if doubled < denominator.unsigned_abs() {
        return Some(quotient);
    }
    let step: i128 = if (remainder > 0) == (denominator > 0) {
        1
    } else {
        -1
    };
    quotient.checked_add(step)
}

fn negated_unsigned_type(operand: &Operand) -> Option<Type> {
    match &operand.kind {
        OperandKind::Negate(inner) | OperandKind::UnaryPlus(inner) => negated_unsigned_type(inner),
        OperandKind::Field { field, .. } => match type_of(field.field_type) {
            ty @ Type::Uint(_) => Some(ty),
            _ => None,
        },
        OperandKind::Function { ty, .. } | OperandKind::Binary { ty, .. } => match ty {
            ty @ Type::Uint(_) => Some(*ty),
            _ => None,
        },
        _ => None,
    }
}

fn resolve_function(
    function: Function,
    arg: &mut Operand,
    ty: &mut Type,
    start: usize,
    end: usize,
) -> Result<Type, FilterError> {
    match function {
        Function::Count => {
            match &arg.kind {
                OperandKind::Field { .. } => {
                    resolve_operand(arg, None)?;
                }
                OperandKind::Protocol { .. } => {}
                _ => {
                    return Err(FilterError::at_span(
                        arg.start,
                        arg.end,
                        "only fields can be used as a parameter for count()".to_string(),
                    ));
                }
            }
            *ty = Type::Uint(32);
            Ok(*ty)
        }
        Function::String => {
            let field_type = bare_field(arg)?;
            let allowed = matches!(
                field_type,
                FieldType::Uint8
                    | FieldType::Uint16
                    | FieldType::Uint24
                    | FieldType::Uint32
                    | FieldType::FrameNumber
                    | FieldType::Uint64
                    | FieldType::Int8
                    | FieldType::Int16
                    | FieldType::Int32
                    | FieldType::Int64
                    | FieldType::String
                    | FieldType::StringZ
                    | FieldType::Ethernet
                    | FieldType::Eui64
                    | FieldType::Ipv4
                    | FieldType::Ipv6
            );
            if !allowed {
                return Err(FilterError::at_span(
                    arg.start,
                    arg.end,
                    "string conversion for this field is not supported".to_string(),
                ));
            }
            *ty = Type::String;
            Ok(*ty)
        }
        Function::Hex => {
            let field_type = bare_field(arg)?;
            if !matches!(
                field_type,
                FieldType::Uint8
                    | FieldType::Uint16
                    | FieldType::Uint24
                    | FieldType::Uint32
                    | FieldType::FrameNumber
                    | FieldType::Uint64
                    | FieldType::Int8
                    | FieldType::Int16
                    | FieldType::Int32
                    | FieldType::Int64
            ) {
                return Err(FilterError::at_span(
                    arg.start,
                    arg.end,
                    "base conversion for this field is not supported".to_string(),
                ));
            }
            *ty = Type::String;
            Ok(*ty)
        }
        Function::Upper | Function::Lower => {
            if !has_field(arg) {
                return Err(constant_error(start, end));
            }
            let arg_type = resolve_operand(arg, Some(Type::String))?;
            if arg_type != Type::String {
                return Err(FilterError::at_span(
                    arg.start,
                    arg.end,
                    "only string fields can be used with upper() or lower()".to_string(),
                ));
            }
            *ty = Type::String;
            Ok(*ty)
        }
        Function::Len => {
            if !has_field(arg) {
                return Err(constant_error(start, end));
            }
            let arg_type = resolve_operand(arg, None)?;
            if !arg_type.is_sequence() {
                return Err(FilterError::at_span(
                    arg.start,
                    arg.end,
                    "argument does not support the len() function".to_string(),
                ));
            }
            *ty = Type::Uint(32);
            Ok(*ty)
        }
        Function::Max | Function::Min => {
            let arg_type = resolve_operand(arg, None)?;
            if !has_field(arg) {
                return Err(constant_error(start, end));
            }
            if matches!(arg_type, Type::Boolean | Type::Protocol) {
                return Err(FilterError::at_span(
                    arg.start,
                    arg.end,
                    "argument cannot be ordered".to_string(),
                ));
            }
            *ty = arg_type;
            Ok(*ty)
        }
        Function::Abs => {
            let arg_type = resolve_operand(arg, None)?;
            if !has_field(arg) {
                return Err(constant_error(start, end));
            }
            if !arg_type.is_numeric() && arg_type != Type::Time {
                return Err(FilterError::at_span(
                    arg.start,
                    arg.end,
                    "argument cannot be negated".to_string(),
                ));
            }
            *ty = arg_type;
            Ok(*ty)
        }
    }
}

fn bare_field(operand: &Operand) -> Result<FieldType, FilterError> {
    match &operand.kind {
        OperandKind::Field { field, .. } => Ok(field.field_type),
        _ => Err(FilterError::at_span(
            operand.start,
            operand.end,
            "only fields can be used as a parameter for this function".to_string(),
        )),
    }
}

fn arith_symbol(operator: ArithOp) -> &'static str {
    match operator {
        ArithOp::Add => "+",
        ArithOp::Subtract => "-",
        ArithOp::Multiply => "*",
        ArithOp::Divide => "/",
        ArithOp::Modulo => "%",
        ArithOp::BitwiseAnd => "&",
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum RuntimeValue<'a> {
    Int(i128),
    Double(f64),
    Bool(bool),
    Text(String),
    Bytes(Bytes),
    Ethernet([u8; 6]),
    Eui64([u8; 8]),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Time { seconds: i64, nanos: u32 },
    Protocol(&'a Node, usize),
}

#[derive(Clone, Debug)]
struct Sequence<'a> {
    ty: Type,
    values: Vec<RuntimeValue<'a>>,
}

impl<'a> Sequence<'a> {
    fn empty(ty: Type) -> Self {
        Self {
            ty,
            values: Vec::new(),
        }
    }

    fn single(ty: Type, value: RuntimeValue<'a>) -> Self {
        Self {
            ty,
            values: vec![value],
        }
    }
}

fn evaluate(expr: &Expr, tree: &Tree) -> bool {
    match expr {
        Expr::Protocol { protocol, layer } => protocol_exists(&tree.frame, protocol, *layer),
        Expr::Field { field, layer } => field_exists(&tree.frame, field, *layer),
        Expr::Truthy(operand) => evaluate_operand(operand, tree).values.iter().any(truthy),
        Expr::Not(inner) => !evaluate(inner, tree),
        Expr::And(left, right) => evaluate(left, tree) && evaluate(right, tree),
        Expr::Or(left, right) => evaluate(left, tree) || evaluate(right, tree),
        Expr::Xor(left, right) => evaluate(left, tree) ^ evaluate(right, tree),
        Expr::Compare {
            left,
            operator,
            right,
        } => {
            let left = evaluate_operand(left, tree);
            let right = evaluate_operand(right, tree);
            compare_sequences(&left, *operator, &right)
        }
        Expr::Contains { left, right } => {
            let left = evaluate_operand(left, tree);
            let right = evaluate_operand(right, tree);
            left.values
                .iter()
                .any(|left| right.values.iter().any(|right| contains_value(left, right)))
        }
        Expr::Matches { left, pattern } => {
            let left = evaluate_operand(left, tree);
            left.values.iter().any(|value| match_value(value, pattern))
        }
        Expr::In {
            field,
            layer,
            members,
        } => in_field(&tree.frame, field, *layer, members, tree),
    }
}

fn truthy(value: &RuntimeValue<'_>) -> bool {
    match value {
        RuntimeValue::Int(value) => *value != 0,
        RuntimeValue::Double(value) => *value != 0.0,
        RuntimeValue::Bool(value) => *value,
        RuntimeValue::Text(value) => !value.is_empty(),
        RuntimeValue::Bytes(value) => !value.is_empty(),
        RuntimeValue::Ethernet(_) | RuntimeValue::Eui64(_) => true,
        RuntimeValue::Ipv4(_) | RuntimeValue::Ipv6(_) => true,
        RuntimeValue::Time { seconds, nanos } => *seconds != 0 || *nanos != 0,
        RuntimeValue::Protocol(..) => true,
    }
}

fn evaluate_operand<'a>(operand: &'a Operand, tree: &'a Tree) -> Sequence<'a> {
    match &operand.kind {
        OperandKind::Field { field, layer } => Sequence {
            ty: type_of(field.field_type),
            values: {
                let mut values = Vec::new();
                for_each_field_value(&tree.frame, field, *layer, &mut |occurrence| {
                    if let Some(value) = runtime_field_value(&occurrence.value, field.field_type) {
                        values.push(value);
                    }
                });
                values
            },
        },
        OperandKind::Protocol { protocol, layer } => Sequence {
            ty: Type::Protocol,
            values: {
                let mut values = Vec::new();
                for_each_protocol_value(&tree.frame, protocol, *layer, &mut |node, ordinal| {
                    values.push(RuntimeValue::Protocol(node, ordinal));
                });
                values
            },
        },
        OperandKind::Slice { inner, slice } => {
            let inner = evaluate_operand(inner, tree);
            let ty = slice_type(inner.ty);
            let values = inner
                .values
                .iter()
                .filter_map(|value| slice_value(value, *slice, ty))
                .collect();
            Sequence { ty, values }
        }
        OperandKind::TokenLiteral(_) => Sequence::empty(Type::Untyped),
        OperandKind::Literal { literal, ty } => Sequence::single(*ty, literal_value(literal)),
        OperandKind::Function { function, arg, ty } => evaluate_function(*function, arg, *ty, tree),
        OperandKind::UnaryPlus(inner) => evaluate_operand(inner, tree),
        OperandKind::Negate(inner) => {
            let inner = evaluate_operand(inner, tree);
            let values = inner
                .values
                .iter()
                .filter_map(|value| match value {
                    RuntimeValue::Int(value) => value.checked_neg().map(RuntimeValue::Int),
                    RuntimeValue::Time { seconds, nanos } => {
                        let total = i128::from(*seconds)
                            .checked_mul(1_000_000_000)?
                            .checked_add(i128::from(*nanos))?;
                        time_value(total.checked_neg()?)
                    }
                    _ => None,
                })
                .collect();
            let ty = match inner.ty {
                Type::Time => Type::Time,
                ty if ty.is_numeric() => Type::Int(64),
                ty => ty,
            };
            Sequence { ty, values }
        }
        OperandKind::Binary {
            operator,
            left,
            right,
            ty,
        } => {
            let left = evaluate_operand(left, tree);
            let right = evaluate_operand(right, tree);
            let mut values = Vec::new();
            for left_value in &left.values {
                for right_value in &right.values {
                    if let Some(value) =
                        apply_arithmetic(*operator, left.ty, left_value, right.ty, right_value, *ty)
                    {
                        values.push(value);
                    }
                }
            }
            Sequence { ty: *ty, values }
        }
    }
}

fn runtime_field_value<'a>(value: &'a Value, field_type: FieldType) -> Option<RuntimeValue<'a>> {
    if field_type == FieldType::Double {
        return match value {
            Value::Uint16(raw) => Some(RuntimeValue::Double(f64::from(*raw) / 256.0)),
            Value::Uint32(raw) => Some(RuntimeValue::Double(f64::from(*raw) / 256.0)),
            _ => None,
        };
    }
    Some(match value {
        Value::Uint8(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Uint16(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Uint24(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Uint32(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Uint64(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Int8(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Int16(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Int32(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Int64(value) => RuntimeValue::Int(i128::from(*value)),
        Value::Boolean(value) => RuntimeValue::Bool(*value),
        Value::None => return None,
        Value::Missing => RuntimeValue::Bytes(Bytes::default()),
        Value::Ethernet(value) => RuntimeValue::Ethernet(*value),
        Value::Eui64(value) => RuntimeValue::Eui64(*value),
        Value::Ipv4(value) => RuntimeValue::Ipv4(*value),
        Value::Ipv6(value) => RuntimeValue::Ipv6(*value),
        Value::String(value) => RuntimeValue::Text(value.clone()),
        Value::Bytes(value) => RuntimeValue::Bytes(value.clone()),
        Value::AbsoluteTime(timestamp) => RuntimeValue::Time {
            seconds: timestamp.seconds,
            nanos: timestamp.nanos,
        },
        Value::Oid(ids) => RuntimeValue::Text(crate::tree::oid_text(ids)),
        Value::RelativeTime(nanos) => RuntimeValue::Int(i128::from(*nanos)),
    })
}

fn literal_value(literal: &Literal) -> RuntimeValue<'static> {
    match literal {
        Literal::Integer(value) => RuntimeValue::Int(*value),
        Literal::Double(value) => RuntimeValue::Double(*value),
        Literal::Boolean(value) => RuntimeValue::Bool(*value),
        Literal::String(value) => RuntimeValue::Text(value.clone()),
        Literal::Bytes(value) => RuntimeValue::Bytes(value.clone()),
        Literal::Ethernet(value) => RuntimeValue::Ethernet(*value),
        Literal::Eui64(value) => RuntimeValue::Eui64(*value),
        Literal::Ipv4(value) => RuntimeValue::Ipv4(*value),
        Literal::Ipv6(value) => RuntimeValue::Ipv6(*value),
        Literal::Time { seconds, nanos } => RuntimeValue::Time {
            seconds: *seconds,
            nanos: *nanos,
        },
    }
}

fn time_value(nanos: i128) -> Option<RuntimeValue<'static>> {
    let seconds = nanos.div_euclid(1_000_000_000);
    let nanos = nanos.rem_euclid(1_000_000_000);
    Some(RuntimeValue::Time {
        seconds: i64::try_from(seconds).ok()?,
        nanos: u32::try_from(nanos).ok()?,
    })
}

fn apply_arithmetic(
    operator: ArithOp,
    left_type: Type,
    left: &RuntimeValue<'_>,
    right_type: Type,
    right: &RuntimeValue<'_>,
    ty: Type,
) -> Option<RuntimeValue<'static>> {
    if ty == Type::Double
        && (left_type == Type::Time || right_type == Type::Time)
        && (left_type == Type::Relative || right_type == Type::Relative)
    {
        // A relative time beside an absolute time: both become seconds, so
        // the result is the numeric duration the comparison literals use.
        let left = arithmetic_seconds(left, left_type)?;
        let right = arithmetic_seconds(right, right_type)?;
        let value = match operator {
            ArithOp::Add => left + right,
            ArithOp::Subtract => left - right,
            ArithOp::Multiply | ArithOp::Divide | ArithOp::Modulo | ArithOp::BitwiseAnd => {
                return None;
            }
        };
        return value.is_finite().then_some(RuntimeValue::Double(value));
    }
    if ty == Type::Double {
        let left = double_value(left)?;
        let right = double_value(right)?;
        let value = match operator {
            ArithOp::Add => left + right,
            ArithOp::Subtract => left - right,
            ArithOp::Multiply => left * right,
            ArithOp::Divide if right != 0.0 => left / right,
            ArithOp::Divide => return None,
            ArithOp::Modulo if right != 0.0 => left % right,
            ArithOp::Modulo => return None,
            ArithOp::BitwiseAnd => return None,
        };
        return value.is_finite().then_some(RuntimeValue::Double(value));
    }
    if ty == Type::Time {
        let left = time_nanos(left)?;
        return match operator {
            ArithOp::Add => time_value(left.checked_add(time_nanos(right)?)?),
            ArithOp::Subtract => time_value(left.checked_sub(time_nanos(right)?)?),
            ArithOp::Multiply => time_value(left.checked_mul(integer_value(right)?)?),
            ArithOp::Divide => {
                let divisor = integer_value(right)?;
                if divisor == 0 {
                    return None;
                }
                time_value(left / divisor)
            }
            ArithOp::Modulo | ArithOp::BitwiseAnd => None,
        };
    }
    let left = integer_value(left)?;
    let right = integer_value(right)?;
    let value = apply_integer(operator, left, right, right_type, ty)?;
    Some(RuntimeValue::Int(value))
}

fn time_nanos(value: &RuntimeValue<'_>) -> Option<i128> {
    match value {
        RuntimeValue::Time { seconds, nanos } => i128::from(*seconds)
            .checked_mul(1_000_000_000)?
            .checked_add(i128::from(*nanos)),
        RuntimeValue::Int(value) => Some(*value),
        _ => None,
    }
}

fn double_value(value: &RuntimeValue<'_>) -> Option<f64> {
    match value {
        RuntimeValue::Double(value) => Some(*value),
        RuntimeValue::Int(value) => Some(*value as f64),
        RuntimeValue::Bool(value) => Some(f64::from(u8::from(*value))),
        _ => None,
    }
}

/// One operand of mixed absolute/relative arithmetic, in seconds.
///
/// Relative fields store nanoseconds, so their integer value is scaled; an
/// absolute time carries whole seconds and a nanosecond fraction.
fn arithmetic_seconds(value: &RuntimeValue<'_>, ty: Type) -> Option<f64> {
    match value {
        RuntimeValue::Time { seconds, nanos } => {
            Some(*seconds as f64 + f64::from(*nanos) / 1_000_000_000.0)
        }
        RuntimeValue::Int(value) if ty == Type::Relative => Some(*value as f64 / 1_000_000_000.0),
        RuntimeValue::Int(value) => Some(*value as f64),
        RuntimeValue::Double(value) => Some(*value),
        _ => None,
    }
}

fn integer_value(value: &RuntimeValue<'_>) -> Option<i128> {
    match value {
        RuntimeValue::Int(value) => Some(*value),
        RuntimeValue::Bool(value) => Some(i128::from(*value)),
        _ => None,
    }
}

fn apply_integer(
    operator: ArithOp,
    left: i128,
    right: i128,
    right_type: Type,
    ty: Type,
) -> Option<i128> {
    let (minimum, maximum) = match ty {
        Type::Uint(bits) => {
            let maximum = (1_i128 << bits.min(127)) - 1;
            (i128::MIN / 4, maximum)
        }
        Type::Int(bits) => {
            let maximum = (1_i128 << (bits.min(127) - 1)) - 1;
            (-maximum - 1, maximum)
        }
        Type::Time => (i128::MIN / 2, i128::MAX / 2),
        Type::Relative => (i128::MIN / 2, i128::MAX / 2),
        Type::Untyped => (i128::MIN / 2, i128::MAX / 2),
        _ => return None,
    };
    let right_ok = match ty {
        Type::Uint(_) => {
            if matches!(right_type, Type::Int(_)) && right < 0 {
                left < 0
            } else {
                right <= maximum
            }
        }
        _ => right >= minimum && right <= maximum,
    };
    let value = match operator {
        ArithOp::BitwiseAnd => left & right,
        _ if !right_ok && operator != ArithOp::BitwiseAnd => return None,
        ArithOp::Add => left.checked_add(right)?,
        ArithOp::Subtract => left.checked_sub(right)?,
        ArithOp::Multiply => left.checked_mul(right)?,
        ArithOp::Divide => {
            if right == 0 {
                return None;
            }
            left.checked_div(right)?
        }
        ArithOp::Modulo => {
            if right == 0 {
                return None;
            }
            left.checked_rem(right)?
        }
    };
    let upper_ok = value <= maximum;
    let lower_ok = match ty {
        Type::Uint(_) => true,
        _ => operator == ArithOp::BitwiseAnd || value >= minimum,
    };
    (upper_ok && lower_ok).then_some(value)
}

fn slice_value<'a>(value: &RuntimeValue<'a>, slice: Slice, ty: Type) -> Option<RuntimeValue<'a>> {
    let (length, is_text) = match value {
        RuntimeValue::Text(text) => (text.chars().count(), true),
        RuntimeValue::Bytes(bytes) => (bytes.len(), false),
        RuntimeValue::Ethernet(bytes) => (bytes.len(), false),
        RuntimeValue::Eui64(bytes) => (bytes.len(), false),
        RuntimeValue::Ipv4(bytes) => (bytes.len(), false),
        RuntimeValue::Ipv6(bytes) => (bytes.len(), false),
        _ => return None,
    };
    let length = i64::try_from(length).ok()?;
    let start = match slice.start {
        Some(start) if start < 0 => length.checked_add(start).unwrap_or(-1),
        Some(start) => start,
        None => 0,
    };
    if start < 0 {
        return Some(empty_slice_value(ty));
    }
    let start = start.min(length);
    let end = match slice.length {
        Some(count) if count > 0 => start.checked_add(count).unwrap_or(i64::MAX),
        Some(_) => return Some(empty_slice_value(ty)),
        None => length,
    };
    if end > length {
        return Some(empty_slice_value(ty));
    }
    let start = usize::try_from(start).ok()?;
    let end = usize::try_from(end).ok()?;
    if is_text {
        let RuntimeValue::Text(text) = value else {
            return None;
        };
        let start_byte = text
            .char_indices()
            .nth(start)
            .map_or(text.len(), |(index, _)| index);
        let end_byte = text
            .char_indices()
            .nth(end)
            .map_or(text.len(), |(index, _)| index);
        let slice = text.get(start_byte..end_byte)?;
        Some(RuntimeValue::Text(slice.to_string()))
    } else if ty == Type::String {
        None
    } else {
        let bytes = raw_bytes(value)?;
        let slice = bytes.get(start..end)?;
        Some(RuntimeValue::Bytes(slice.into()))
    }
}

fn empty_slice_value(ty: Type) -> RuntimeValue<'static> {
    if ty == Type::String {
        RuntimeValue::Text(String::new())
    } else {
        RuntimeValue::Bytes(Bytes::default())
    }
}

fn raw_bytes<'a>(value: &'a RuntimeValue<'_>) -> Option<&'a [u8]> {
    match value {
        RuntimeValue::Bytes(bytes) => Some(bytes),
        RuntimeValue::Ethernet(bytes) => Some(bytes),
        RuntimeValue::Eui64(bytes) => Some(bytes),
        RuntimeValue::Ipv4(bytes) => Some(bytes),
        RuntimeValue::Ipv6(bytes) => Some(bytes),
        RuntimeValue::Text(text) => Some(text.as_bytes()),
        _ => None,
    }
}

fn evaluate_function<'a>(
    function: Function,
    arg: &'a Operand,
    ty: Type,
    tree: &'a Tree,
) -> Sequence<'a> {
    match function {
        Function::Count => {
            let count = match &arg.kind {
                OperandKind::Field { field, layer } => {
                    let mut count = 0_u64;
                    for_each_field_value(&tree.frame, field, *layer, &mut |_| {
                        count = count.saturating_add(1);
                    });
                    count
                }
                OperandKind::Protocol { protocol, layer } => {
                    let mut count = 0_u64;
                    for_each_protocol(&tree.frame, protocol, *layer, &mut |_| {
                        count = count.saturating_add(1);
                    });
                    count
                }
                _ => 0,
            };
            Sequence::single(ty, RuntimeValue::Int(i128::from(count)))
        }
        Function::Len => {
            let arg = evaluate_operand(arg, tree);
            let values = arg
                .values
                .iter()
                .filter_map(|value| {
                    let length = match value {
                        RuntimeValue::Text(text) => u64::try_from(text.chars().count()).ok()?,
                        RuntimeValue::Bytes(bytes) => u64::try_from(bytes.len()).ok()?,
                        RuntimeValue::Ethernet(bytes) => u64::try_from(bytes.len()).ok()?,
                        RuntimeValue::Eui64(bytes) => u64::try_from(bytes.len()).ok()?,
                        RuntimeValue::Ipv4(bytes) => u64::try_from(bytes.len()).ok()?,
                        RuntimeValue::Ipv6(bytes) => u64::try_from(bytes.len()).ok()?,
                        RuntimeValue::Protocol(node, _) => {
                            u64::try_from(protocol_length(node)).ok()?
                        }
                        _ => return None,
                    };
                    Some(RuntimeValue::Int(i128::from(length)))
                })
                .collect();
            Sequence { ty, values }
        }
        Function::Upper | Function::Lower => {
            let arg = evaluate_operand(arg, tree);
            let values = arg
                .values
                .iter()
                .filter_map(|value| match value {
                    RuntimeValue::Text(text) => {
                        Some(RuntimeValue::Text(if function == Function::Upper {
                            text.to_ascii_uppercase()
                        } else {
                            text.to_ascii_lowercase()
                        }))
                    }
                    _ => None,
                })
                .collect();
            Sequence { ty, values }
        }
        Function::String => {
            let arg = evaluate_operand(arg, tree);
            let values = arg
                .values
                .iter()
                .filter_map(|value| Some(RuntimeValue::Text(display_value(value)?)))
                .collect();
            Sequence { ty, values }
        }
        Function::Hex => {
            let width = match &arg.kind {
                OperandKind::Field { field, .. } => field_bits(field.field_type),
                _ => None,
            };
            let arg = evaluate_operand(arg, tree);
            let values = arg
                .values
                .iter()
                .filter_map(|value| {
                    let value = integer_value(value)?;
                    let width = width?;
                    let mask = if width >= 32 {
                        u128::MAX
                    } else {
                        (1_u128 << (width * 4)) - 1
                    };
                    let masked = (value as u128) & mask;
                    Some(RuntimeValue::Text(format!("0x{masked:0width$x}")))
                })
                .collect();
            Sequence { ty, values }
        }
        Function::Max | Function::Min => {
            let arg = evaluate_operand(arg, tree);
            let mut selected: Option<&RuntimeValue<'_>> = None;
            for value in &arg.values {
                selected = Some(match selected {
                    None => value,
                    Some(current) => {
                        let ordering = compare_runtime(value, current);
                        let replace = match function {
                            Function::Max => ordering == Some(Ordering::Greater),
                            Function::Min => ordering == Some(Ordering::Less),
                            _ => false,
                        };
                        if replace { value } else { current }
                    }
                });
            }
            match selected {
                Some(value) => Sequence::single(ty, value.clone()),
                None => Sequence::empty(ty),
            }
        }
        Function::Abs => {
            let arg = evaluate_operand(arg, tree);
            let values = arg
                .values
                .iter()
                .filter_map(|value| match value {
                    RuntimeValue::Int(value) => value.checked_abs().map(RuntimeValue::Int),
                    RuntimeValue::Time { seconds, nanos } => {
                        let total = i128::from(*seconds)
                            .checked_mul(1_000_000_000)?
                            .checked_add(i128::from(*nanos))?;
                        time_value(total.checked_abs()?)
                    }
                    _ => None,
                })
                .collect();
            Sequence { ty, values }
        }
    }
}

fn field_bits(field_type: FieldType) -> Option<usize> {
    let bits = match field_type {
        FieldType::Uint8 | FieldType::Int8 => 8,
        FieldType::Uint16 | FieldType::Int16 => 16,
        FieldType::Uint24 => 24,
        FieldType::Uint32 | FieldType::Int32 | FieldType::FrameNumber => 32,
        FieldType::Uint64 | FieldType::Int64 => 64,
        _ => return None,
    };
    Some(bits / 4)
}

fn display_value(value: &RuntimeValue<'_>) -> Option<String> {
    match value {
        RuntimeValue::Int(value) => Some(value.to_string()),
        RuntimeValue::Double(value) => Some(value.to_string()),
        RuntimeValue::Text(value) => Some(value.clone()),
        RuntimeValue::Ethernet(address) => Some(format_ethernet(address)),
        RuntimeValue::Eui64(address) => Some(format_eui64(address)),
        RuntimeValue::Ipv4(address) => Some(format_ipv4(address)),
        RuntimeValue::Ipv6(address) => Some(crate::tree::format_ipv6(address)),
        _ => None,
    }
}

fn format_ethernet(address: &[u8; 6]) -> String {
    let mut parts = Vec::with_capacity(6);
    for byte in address {
        parts.push(format!("{byte:02x}"));
    }
    parts.join(":")
}

fn format_eui64(address: &[u8; 8]) -> String {
    let mut parts = Vec::with_capacity(8);
    for byte in address {
        parts.push(format!("{byte:02x}"));
    }
    parts.join(":")
}

fn format_ipv4(address: &[u8; 4]) -> String {
    let [first, second, third, fourth] = address;
    format!("{first}.{second}.{third}.{fourth}")
}

fn compare_sequences(left: &Sequence<'_>, operator: CompareOp, right: &Sequence<'_>) -> bool {
    if left.values.is_empty() || right.values.is_empty() {
        return false;
    }
    match operator {
        CompareOp::AnyEq => left.values.iter().any(|left| {
            right
                .values
                .iter()
                .any(|right| compare_runtime(left, right) == Some(Ordering::Equal))
        }),
        CompareOp::AllEq => left.values.iter().all(|left| {
            right
                .values
                .iter()
                .all(|right| compare_runtime(left, right) == Some(Ordering::Equal))
        }),
        CompareOp::AnyNe => left.values.iter().any(|left| {
            right
                .values
                .iter()
                .any(|right| compare_runtime(left, right) != Some(Ordering::Equal))
        }),
        CompareOp::AllNe => left.values.iter().all(|left| {
            right
                .values
                .iter()
                .all(|right| compare_runtime(left, right) != Some(Ordering::Equal))
        }),
        CompareOp::AnyLt => left.values.iter().any(|left| {
            right
                .values
                .iter()
                .any(|right| compare_runtime(left, right) == Some(Ordering::Less))
        }),
        CompareOp::AnyGt => left.values.iter().any(|left| {
            right
                .values
                .iter()
                .any(|right| compare_runtime(left, right) == Some(Ordering::Greater))
        }),
        CompareOp::AnyLe => left.values.iter().any(|left| {
            right.values.iter().any(|right| {
                matches!(
                    compare_runtime(left, right),
                    Some(Ordering::Less | Ordering::Equal)
                )
            })
        }),
        CompareOp::AnyGe => left.values.iter().any(|left| {
            right.values.iter().any(|right| {
                matches!(
                    compare_runtime(left, right),
                    Some(Ordering::Greater | Ordering::Equal)
                )
            })
        }),
    }
}

fn compare_runtime(left: &RuntimeValue<'_>, right: &RuntimeValue<'_>) -> Option<Ordering> {
    match (left, right) {
        (RuntimeValue::Int(left), RuntimeValue::Int(right)) => Some(left.cmp(right)),
        (RuntimeValue::Double(left), RuntimeValue::Double(right)) => left.partial_cmp(right),
        (RuntimeValue::Double(left), RuntimeValue::Int(right)) => {
            left.partial_cmp(&(*right as f64))
        }
        (RuntimeValue::Int(left), RuntimeValue::Double(right)) => (*left as f64).partial_cmp(right),
        (RuntimeValue::Bool(left), RuntimeValue::Bool(right)) => Some(left.cmp(right)),
        (RuntimeValue::Text(left), RuntimeValue::Text(right)) => Some(left.as_str().cmp(right)),
        (RuntimeValue::Bytes(left), RuntimeValue::Bytes(right)) => Some(left.cmp(right)),
        (RuntimeValue::Ethernet(left), RuntimeValue::Ethernet(right)) => Some(left.cmp(right)),
        (RuntimeValue::Eui64(left), RuntimeValue::Eui64(right)) => Some(left.cmp(right)),
        (RuntimeValue::Ipv4(left), RuntimeValue::Ipv4(right)) => Some(left.cmp(right)),
        (RuntimeValue::Ipv6(left), RuntimeValue::Ipv6(right)) => Some(left.cmp(right)),
        (RuntimeValue::Ethernet(left), RuntimeValue::Bytes(right)) => {
            Some(left.as_slice().cmp(right.as_slice()))
        }
        (RuntimeValue::Bytes(left), RuntimeValue::Ethernet(right)) => {
            Some(left.as_slice().cmp(right.as_slice()))
        }
        (RuntimeValue::Eui64(left), RuntimeValue::Bytes(right)) => {
            Some(left.as_slice().cmp(right.as_slice()))
        }
        (RuntimeValue::Bytes(left), RuntimeValue::Eui64(right)) => {
            Some(left.as_slice().cmp(right.as_slice()))
        }
        (
            RuntimeValue::Time {
                seconds: left_seconds,
                nanos: left_nanos,
            },
            RuntimeValue::Time {
                seconds: right_seconds,
                nanos: right_nanos,
            },
        ) => Some((left_seconds, left_nanos).cmp(&(right_seconds, right_nanos))),
        (
            RuntimeValue::Protocol(left_node, left_ordinal),
            RuntimeValue::Protocol(right_node, right_ordinal),
        ) => {
            if std::ptr::eq(*left_node, *right_node) {
                Some(Ordering::Equal)
            } else if left_node.protocol.filter_name == right_node.protocol.filter_name {
                Some(left_ordinal.cmp(right_ordinal))
            } else {
                Some(
                    protocol_rank(left_node)
                        .cmp(&protocol_rank(right_node))
                        .then_with(|| {
                            left_node
                                .protocol
                                .filter_name
                                .cmp(right_node.protocol.filter_name)
                        }),
                )
            }
        }
        _ => None,
    }
}

fn contains_value(left: &RuntimeValue<'_>, right: &RuntimeValue<'_>) -> bool {
    let needle = raw_bytes(right).filter(|needle| !needle.is_empty());
    let Some(needle) = needle else {
        return false;
    };
    match left {
        RuntimeValue::Text(text) => text
            .as_bytes()
            .windows(needle.len())
            .any(|window| window == needle),
        _ => raw_bytes(left).is_some_and(|haystack| {
            haystack
                .windows(needle.len())
                .any(|window| window == needle)
        }),
    }
}

fn match_value(value: &RuntimeValue<'_>, pattern: &Pattern) -> bool {
    raw_bytes(value).is_some_and(|bytes| pattern.regex.is_match(bytes))
}

fn in_field(
    root: &Node,
    field: &'static FieldDef,
    layer: Option<u64>,
    members: &[InMember],
    tree: &Tree,
) -> bool {
    let mut found = false;
    for_each_field_value(root, field, layer, &mut |occurrence| {
        if found {
            return;
        }
        let Some(value) = runtime_field_value(&occurrence.value, field.field_type) else {
            return;
        };
        found = members.iter().any(|member| match member {
            InMember::Value(operand) => evaluate_operand(operand, tree)
                .values
                .iter()
                .any(|expected| compare_runtime(&value, expected) == Some(Ordering::Equal)),
            InMember::Range(start, end) => {
                let start = evaluate_operand(start, tree);
                let end = evaluate_operand(end, tree);
                start.values.iter().any(|start| {
                    end.values.iter().any(|end| {
                        matches!(
                            (compare_runtime(&value, start), compare_runtime(&value, end)),
                            (Some(from), Some(to))
                                if from != Ordering::Less && to != Ordering::Greater
                        )
                    })
                })
            }
            InMember::Cidr { network, prefix } => cidr_contains(&value, network, *prefix),
        });
    });
    found
}

fn cidr_contains(value: &RuntimeValue<'_>, network: &Literal, prefix: u8) -> bool {
    match (value, network) {
        (RuntimeValue::Ipv4(value), Literal::Ipv4(network)) => {
            prefix_matches(value, network, prefix)
        }
        (RuntimeValue::Ipv6(value), Literal::Ipv6(network)) => {
            prefix_matches(value, network, prefix)
        }
        _ => false,
    }
}

fn prefix_matches(value: &[u8], network: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    let remainder = prefix % 8;
    for (value, network) in value.iter().zip(network).take(full) {
        if value != network {
            return false;
        }
    }
    if remainder == 0 {
        return true;
    }
    let mask = 0xff_u8 << (8 - remainder);
    matches!(
        (value.get(full), network.get(full)),
        (Some(value), Some(network)) if (value & mask) == (network & mask)
    )
}

fn protocol_length(node: &Node) -> usize {
    let name = node.protocol.filter_name;
    match name {
        "frame" | "dns" | "mdns" | "llmnr" | "data" | "raw" => node.range.length,
        "eth" => 14,
        "vlan" | "ieee8021ad" => 4,
        "sll" => {
            if node
                .fields
                .iter()
                .any(|field| field.def.abbrev == "sll.ifindex")
            {
                20
            } else {
                16
            }
        }
        "null" => 4,
        "llc" => {
            let has_type_or_oui = node
                .fields
                .iter()
                .any(|field| matches!(field.def.abbrev, "llc.type" | "llc.oui"));
            let has_control = field_integer(node, "llc.control").is_some();
            let snap_prefix = field_integer(node, "llc.dsap") == Some(0xaa)
                && field_integer(node, "llc.ssap") == Some(0xaa);
            if has_type_or_oui || (snap_prefix && has_control) {
                8
            } else if snap_prefix {
                2
            } else if has_control {
                3
            } else if field_integer(node, "llc.ssap").is_some() {
                2
            } else {
                1
            }
        }
        "arp" => {
            let hw = field_integer(node, "arp.hw.size").unwrap_or(6);
            let proto = field_integer(node, "arp.proto.size").unwrap_or(4);
            8_usize
                .saturating_add(2_usize.saturating_mul(hw))
                .saturating_add(2_usize.saturating_mul(proto))
        }
        "ip" => field_integer(node, "ip.hdr_len").unwrap_or(20),
        "tcp" => field_integer(node, "tcp.hdr_len").unwrap_or(20),
        "udp" => 8,
        "ipv6" => {
            let mut length = 40_usize;
            for child in &node.children {
                if is_ipv6_extension(child.protocol.filter_name) {
                    length = length.saturating_add(extension_chain_length(child));
                }
            }
            length
        }
        "icmp" | "icmpv6" => node.range.length,
        "ipv6.hopopts" => declared_extension_length(node, "ipv6.hopopts.len"),
        "ipv6.dstopts" => declared_extension_length(node, "ipv6.dstopts.len"),
        "ipv6.routing" => {
            let declared = field_integer(node, "ipv6.routing.len")
                .map(|len| len.saturating_add(1).saturating_mul(8));
            declared.map_or(node.range.length, |declared| {
                declared.min(node.range.length)
            })
        }
        "ipv6.fraghdr" => union_length(node),
        _ => {
            let length = union_length(node);
            if length == 0 {
                node.range.length
            } else {
                length
            }
        }
    }
}

fn declared_extension_length(node: &Node, field: &str) -> usize {
    field_integer(node, field)
        .map(|len| len.saturating_add(1).saturating_mul(8))
        .unwrap_or_else(|| union_length(node))
}

fn is_ipv6_extension(name: &str) -> bool {
    matches!(
        name,
        "ipv6.hopopts" | "ipv6.routing" | "ipv6.dstopts" | "ipv6.fraghdr"
    )
}

fn extension_chain_length(node: &Node) -> usize {
    let mut length = captured_extension_length(node);
    for child in &node.children {
        if is_ipv6_extension(child.protocol.filter_name) {
            length = length.saturating_add(extension_chain_length(child));
        }
    }
    length
}

fn captured_extension_length(node: &Node) -> usize {
    if node.fields.is_empty() {
        return 0;
    }
    let name = node.protocol.filter_name;
    match name {
        "ipv6.fraghdr" => union_length(node),
        "ipv6.hopopts" => field_integer(node, "ipv6.hopopts.len")
            .map(|len| len.saturating_add(1).saturating_mul(8))
            .unwrap_or(0)
            .min(node.range.length),
        "ipv6.dstopts" => field_integer(node, "ipv6.dstopts.len")
            .map(|len| len.saturating_add(1).saturating_mul(8))
            .unwrap_or(0)
            .min(node.range.length),
        "ipv6.routing" => field_integer(node, "ipv6.routing.len")
            .map(|len| len.saturating_add(1).saturating_mul(8))
            .unwrap_or(0)
            .min(node.range.length),
        _ => node.range.length,
    }
}

fn field_integer(node: &Node, abbrev: &str) -> Option<usize> {
    for field in &node.fields {
        if field.def.abbrev == abbrev
            && let Some(value) = field.value.clone().into_integer()
        {
            return usize::try_from(value).ok();
        }
    }
    None
}

trait ValueInteger {
    fn into_integer(self) -> Option<i128>;
}

impl ValueInteger for Value {
    fn into_integer(self) -> Option<i128> {
        match self {
            Value::Uint8(value) => Some(i128::from(value)),
            Value::Uint16(value) => Some(i128::from(value)),
            Value::Uint24(value) => Some(i128::from(value)),
            Value::Uint32(value) => Some(i128::from(value)),
            Value::Uint64(value) => Some(i128::from(value)),
            Value::Int8(value) => Some(i128::from(value)),
            Value::Int16(value) => Some(i128::from(value)),
            Value::Int32(value) => Some(i128::from(value)),
            Value::Int64(value) => Some(i128::from(value)),
            _ => None,
        }
    }
}

fn union_length(node: &Node) -> usize {
    let mut ranges = Vec::with_capacity(node.fields.len());
    for field in &node.fields {
        if field.is_container() || field.range.length == 0 {
            continue;
        }
        let start = field.range.offset;
        let end = start.saturating_add(field.range.length);
        ranges.push((start, end));
    }
    ranges.sort_unstable();
    let mut total = 0_usize;
    let mut current: Option<(usize, usize)> = None;
    for (start, end) in ranges {
        match current {
            None => current = Some((start, end)),
            Some((current_start, current_end)) if start <= current_end => {
                current = Some((current_start, current_end.max(end)));
            }
            Some((current_start, current_end)) => {
                total = total.saturating_add(current_end.saturating_sub(current_start));
                current = Some((start, end));
            }
        }
    }
    if let Some((start, end)) = current {
        total = total.saturating_add(end.saturating_sub(start));
    }
    total
}

fn protocol_exists(root: &Node, protocol: &'static ProtocolDef, layer: Option<u64>) -> bool {
    match layer {
        Some(layer) => nth_protocol(root, protocol.filter_name, layer).is_some(),
        None => has_protocol(root, protocol),
    }
}

fn has_protocol(node: &Node, protocol: &'static ProtocolDef) -> bool {
    std::ptr::eq(node.protocol, protocol)
        || node
            .children
            .iter()
            .any(|child| has_protocol(child, protocol))
}

fn field_exists(root: &Node, field: &'static FieldDef, layer: Option<u64>) -> bool {
    let mut seen = false;
    for_each_field_value(root, field, layer, &mut |_| seen = true);
    seen
}

fn for_each_protocol<'a>(
    root: &'a Node,
    protocol: &'static ProtocolDef,
    layer: Option<u64>,
    visit: &mut impl FnMut(&'a Node),
) {
    if let Some(layer) = layer {
        if let Some(node) = nth_protocol(root, protocol.filter_name, layer) {
            visit(node);
        }
        return;
    }
    visit_protocols(root, protocol, visit);
}

fn visit_protocols<'a>(
    node: &'a Node,
    protocol: &'static ProtocolDef,
    visit: &mut impl FnMut(&'a Node),
) {
    if std::ptr::eq(node.protocol, protocol) {
        visit(node);
    }
    for child in &node.children {
        visit_protocols(child, protocol, visit);
    }
}

/// The `#N` operator selects the Nth layer with a protocol filter name,
/// counting from one in preorder. Zero selects no layer.
fn nth_protocol<'a>(root: &'a Node, name: &str, layer: u64) -> Option<&'a Node> {
    if layer == 0 {
        return None;
    }
    let mut remaining = layer;
    find_nth_protocol(root, name, &mut remaining)
}

fn find_nth_protocol<'a>(node: &'a Node, name: &str, remaining: &mut u64) -> Option<&'a Node> {
    if node.protocol.filter_name == name {
        if *remaining == 1 {
            return Some(node);
        }
        *remaining = remaining.saturating_sub(1);
    }
    for child in &node.children {
        if let Some(found) = find_nth_protocol(child, name, remaining) {
            return Some(found);
        }
    }
    None
}

/// The Nth protocol node that a field's `#N` selector counts. DNS fields are
/// carried by the mDNS and LLMNR nodes too, so those names act as aliases of
/// the `dns` parent for layer selection.
fn nth_field_protocol<'a>(root: &'a Node, parent: &str, layer: u64) -> Option<&'a Node> {
    if layer == 0 {
        return None;
    }
    let mut remaining = layer;
    find_nth_field_protocol(root, parent, &mut remaining)
}

fn find_nth_field_protocol<'a>(
    node: &'a Node,
    parent: &str,
    remaining: &mut u64,
) -> Option<&'a Node> {
    let name = node.protocol.filter_name;
    let matches = name == parent || (parent == "dns" && matches!(name, "mdns" | "llmnr"));
    if matches {
        if *remaining == 1 {
            return Some(node);
        }
        *remaining = remaining.saturating_sub(1);
    }
    for child in &node.children {
        if let Some(found) = find_nth_field_protocol(child, parent, remaining) {
            return Some(found);
        }
    }
    None
}

fn for_each_protocol_value<'a>(
    root: &'a Node,
    protocol: &'static ProtocolDef,
    layer: Option<u64>,
    visit: &mut impl FnMut(&'a Node, usize),
) {
    if let Some(layer) = layer {
        if let Some(node) = nth_protocol(root, protocol.filter_name, layer) {
            let ordinal = protocol_ordinal(root, node).unwrap_or(0);
            visit(node, ordinal);
        }
        return;
    }
    let mut ordinal = 0_usize;
    visit_protocol_values(root, protocol, &mut ordinal, visit);
}

fn visit_protocol_values<'a>(
    node: &'a Node,
    protocol: &'static ProtocolDef,
    ordinal: &mut usize,
    visit: &mut impl FnMut(&'a Node, usize),
) {
    let current = *ordinal;
    *ordinal = ordinal.saturating_add(1);
    if std::ptr::eq(node.protocol, protocol) {
        visit(node, current);
    }
    for child in &node.children {
        visit_protocol_values(child, protocol, ordinal, visit);
    }
}

fn protocol_ordinal(root: &Node, target: &Node) -> Option<usize> {
    let mut ordinal = 0_usize;
    protocol_ordinal_from(root, target, &mut ordinal)
}

fn protocol_ordinal_from(node: &Node, target: &Node, ordinal: &mut usize) -> Option<usize> {
    let current = *ordinal;
    *ordinal = ordinal.saturating_add(1);
    if std::ptr::eq(node, target) {
        return Some(current);
    }
    for child in &node.children {
        if let Some(found) = protocol_ordinal_from(child, target, ordinal) {
            return Some(found);
        }
    }
    None
}

/// Rank of a protocol when comparing values of different protocols.
///
/// The ranks order frame > dns > ip > eth > udp and icmp > tcp > ip; other
/// protocols sort below them and tie-break by filter name.
fn protocol_rank(node: &Node) -> u8 {
    match node.protocol.filter_name {
        "icmp" => 8,
        "tcp" => 7,
        "frame" => 5,
        "dns" | "mdns" | "llmnr" => 4,
        "ip" => 3,
        "eth" => 2,
        "udp" => 1,
        _ => 0,
    }
}

fn for_each_field<'a>(node: &'a Node, visit: &mut impl FnMut(&'a Field)) {
    for field in &node.fields {
        field.for_each_in_subtree(visit);
    }
    for child in &node.children {
        for_each_field(child, visit);
    }
}

/// Visit the occurrences of `field` either across the tree or in the layer
/// selected by `#N` (the Nth instance of the field's parent protocol).
fn for_each_field_value<'a>(
    root: &'a Node,
    field: &'static FieldDef,
    layer: Option<u64>,
    visit: &mut impl FnMut(&'a Field),
) {
    match layer {
        Some(layer) => {
            let Some(node) = nth_field_protocol(root, field.parent, layer) else {
                return;
            };
            for occurrence in &node.fields {
                occurrence.for_each_in_subtree(&mut |candidate| {
                    if candidate.def.abbrev == field.abbrev {
                        visit(candidate);
                    }
                });
            }
        }
        None => for_each_field(root, &mut |occurrence| {
            if occurrence.def.abbrev == field.abbrev {
                visit(occurrence);
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Word(String),
    Quoted(Vec<u8>),
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    Colon,
    Eq,
    AllEq,
    Ne,
    AnyNe,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
    Xor,
    Not,
    Tilde,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Ampersand,
    Hash(u64),
    LeftBrace,
    RightBrace,
    Comma,
    RangeDots,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    kind: Kind,
    start: usize,
    end: usize,
}

struct Lexer<'a> {
    text: &'a str,
    index: usize,
    bracket_depth: usize,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            index: 0,
            bracket_depth: 0,
        }
    }

    fn lex(mut self) -> Result<Vec<Token>, FilterError> {
        let mut tokens = Vec::new();
        while let Some(character) = self.peek() {
            if character.is_whitespace() {
                self.index = self.index.saturating_add(character.len_utf8());
                continue;
            }
            let start = self.index;
            let kind = match character {
                '(' => {
                    self.index = self.index.saturating_add(1);
                    Kind::LeftParen
                }
                ')' => {
                    self.index = self.index.saturating_add(1);
                    Kind::RightParen
                }
                '[' => {
                    self.index = self.index.saturating_add(1);
                    self.bracket_depth = self.bracket_depth.saturating_add(1);
                    Kind::LeftBracket
                }
                ']' => {
                    self.index = self.index.saturating_add(1);
                    self.bracket_depth = self.bracket_depth.saturating_sub(1);
                    Kind::RightBracket
                }
                ':' if self.bracket_depth > 0 => {
                    self.index = self.index.saturating_add(1);
                    Kind::Colon
                }
                '{' => {
                    self.index = self.index.saturating_add(1);
                    Kind::LeftBrace
                }
                '}' => {
                    self.index = self.index.saturating_add(1);
                    Kind::RightBrace
                }
                ',' => {
                    self.index = self.index.saturating_add(1);
                    Kind::Comma
                }
                '#' => {
                    self.index = self.index.saturating_add(1);
                    let digits = self.index;
                    while self
                        .peek()
                        .is_some_and(|character| character.is_ascii_digit())
                    {
                        self.index = self.index.saturating_add(1);
                    }
                    if self.index == digits {
                        return Err(FilterError::new(
                            start,
                            Some(1),
                            "a layer number is required after '#'".to_string(),
                        ));
                    }
                    let text = self.text.get(digits..self.index).unwrap_or_default();
                    let layer = text.parse::<u64>().map_err(|_| {
                        FilterError::new(
                            start,
                            Some(self.index.saturating_sub(start)),
                            "the layer number after '#' is too large".to_string(),
                        )
                    })?;
                    if layer > u64::from(i32::MAX as u32) {
                        return Err(FilterError::new(
                            start,
                            Some(self.index.saturating_sub(start)),
                            "the layer number after '#' is too large".to_string(),
                        ));
                    }
                    Kind::Hash(layer)
                }
                '.' => {
                    if self.starts_with("..") {
                        self.index = self.index.saturating_add(2);
                        Kind::RangeDots
                    } else {
                        Kind::Word(self.word())
                    }
                }
                '"' => Kind::Quoted(self.quoted()?),
                '=' => {
                    if self.starts_with("===") {
                        self.index = self.index.saturating_add(3);
                        Kind::AllEq
                    } else if self.starts_with("==") {
                        self.index = self.index.saturating_add(2);
                        Kind::Eq
                    } else {
                        return Err(FilterError::new(
                            start,
                            Some(1),
                            "a single \"=\" is not a display-filter operator".to_string(),
                        ));
                    }
                }
                '!' => {
                    if self.starts_with("!==") {
                        self.index = self.index.saturating_add(3);
                        Kind::AnyNe
                    } else if self.starts_with("!=") {
                        self.index = self.index.saturating_add(2);
                        Kind::Ne
                    } else {
                        self.index = self.index.saturating_add(1);
                        Kind::Not
                    }
                }
                '<' => {
                    if self.starts_with("<=") {
                        self.index = self.index.saturating_add(2);
                        Kind::Le
                    } else {
                        self.index = self.index.saturating_add(1);
                        Kind::Lt
                    }
                }
                '>' => {
                    if self.starts_with(">=") {
                        self.index = self.index.saturating_add(2);
                        Kind::Ge
                    } else {
                        self.index = self.index.saturating_add(1);
                        Kind::Gt
                    }
                }
                '&' => {
                    if self.starts_with("&&") {
                        self.index = self.index.saturating_add(2);
                        Kind::And
                    } else {
                        self.index = self.index.saturating_add(1);
                        Kind::Ampersand
                    }
                }
                '|' => {
                    if self.starts_with("||") {
                        self.index = self.index.saturating_add(2);
                        Kind::Or
                    } else {
                        return Err(FilterError::new(
                            start,
                            Some(1),
                            "\"|\" is not a display-filter operator".to_string(),
                        ));
                    }
                }
                '^' => {
                    if self.starts_with("^^") {
                        self.index = self.index.saturating_add(2);
                        Kind::Xor
                    } else {
                        return Err(FilterError::new(
                            start,
                            Some(1),
                            "\"^\" is not a display-filter operator".to_string(),
                        ));
                    }
                }
                '~' => {
                    if self.starts_with("~=") {
                        return Err(FilterError::new(
                            start.saturating_add(1),
                            Some(1),
                            "\"=\" cannot follow \"~\"".to_string(),
                        ));
                    }
                    self.index = self.index.saturating_add(1);
                    Kind::Tilde
                }
                '\'' => {
                    return Err(FilterError::new(
                        start,
                        Some(1),
                        "character constants are not supported in display filters".to_string(),
                    ));
                }
                '*' => {
                    self.index = self.index.saturating_add(1);
                    Kind::Star
                }
                '%' => {
                    self.index = self.index.saturating_add(1);
                    Kind::Percent
                }
                '/' => {
                    self.index = self.index.saturating_add(1);
                    Kind::Slash
                }
                '+' => {
                    self.index = self.index.saturating_add(1);
                    Kind::Plus
                }
                '-' => {
                    self.index = self.index.saturating_add(1);
                    Kind::Minus
                }
                _ => {
                    let word = self.word();
                    Kind::Word(word)
                }
            };
            tokens.push(Token {
                kind,
                start,
                end: self.index,
            });
        }
        Ok(tokens)
    }

    fn peek(&self) -> Option<char> {
        self.text.get(self.index..)?.chars().next()
    }

    fn starts_with(&self, prefix: &str) -> bool {
        self.text
            .get(self.index..)
            .is_some_and(|rest| rest.starts_with(prefix))
    }

    fn word(&mut self) -> String {
        let start = self.index;
        while let Some(character) = self.peek() {
            if character == '.' && self.starts_with("..") {
                break;
            }
            if character.is_whitespace() || is_delimiter(character, self.bracket_depth > 0) {
                break;
            }
            self.index = self.index.saturating_add(character.len_utf8());
        }
        self.text
            .get(start..self.index)
            .unwrap_or_default()
            .to_string()
    }

    /// Read a quoted string as raw bytes.
    ///
    /// Escape bytes are kept as bytes: `\\xbe` is the single byte `0xbe`,
    /// not a UTF-8 encoding of U+00BE. `\\u` escapes are decoded to their
    /// Unicode character and then encoded as UTF-8, so `"\\u00e9"` matches
    /// `c3:a9` in a byte field.
    fn quoted(&mut self) -> Result<Vec<u8>, FilterError> {
        self.index = self.index.saturating_add(1);
        let mut value = Vec::new();
        loop {
            let Some(character) = self.peek() else {
                return Err(FilterError::at_end(
                    self.text.len(),
                    "the final quote is missing from a quoted string",
                ));
            };
            match character {
                '"' => {
                    self.index = self.index.saturating_add(1);
                    return Ok(value);
                }
                '\\' => {
                    let escape = self.index;
                    self.index = self.index.saturating_add(1);
                    let Some(escaped) = self.peek() else {
                        return Err(FilterError::at_end(
                            self.text.len(),
                            "the final quote is missing from a quoted string",
                        ));
                    };
                    self.index = self.index.saturating_add(escaped.len_utf8());
                    match escaped {
                        'n' => value.push(b'\n'),
                        'r' => value.push(b'\r'),
                        't' => value.push(b'\t'),
                        'a' => value.push(0x07),
                        'b' => value.push(0x08),
                        'f' => value.push(0x0c),
                        'v' => value.push(0x0b),
                        '\\' => value.push(b'\\'),
                        '"' => value.push(b'"'),
                        '\'' => value.push(b'\''),
                        '0' => value.push(0),
                        'x' => {
                            let high = self.hex_digit().ok_or_else(|| {
                                FilterError::new(
                                    escape,
                                    Some(2),
                                    "an \\x escape needs two hexadecimal digits".to_string(),
                                )
                            })?;
                            let low = self.hex_digit().ok_or_else(|| {
                                FilterError::new(
                                    escape,
                                    Some(2),
                                    "an \\x escape needs two hexadecimal digits".to_string(),
                                )
                            })?;
                            value.push((high << 4) | low);
                        }
                        'u' => {
                            let mut scalar = 0_u32;
                            for _ in 0..4 {
                                let digit = self.hex_digit().ok_or_else(|| {
                                    FilterError::new(
                                        escape,
                                        Some(2),
                                        "a \\u escape needs four hexadecimal digits".to_string(),
                                    )
                                })?;
                                scalar = (scalar << 4) | u32::from(digit);
                            }
                            let Some(character) = char::from_u32(scalar) else {
                                return Err(FilterError::new(
                                    escape,
                                    Some(2),
                                    "a \\u escape is not a Unicode scalar value".to_string(),
                                ));
                            };
                            let mut encoded = [0_u8; 4];
                            value.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                        }
                        other => {
                            return Err(FilterError::new(
                                escape,
                                Some(1_usize.saturating_add(other.len_utf8())),
                                format!("unknown string escape \\{other}"),
                            ));
                        }
                    }
                }
                _ => {
                    let mut encoded = [0_u8; 4];
                    value.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                    self.index = self.index.saturating_add(character.len_utf8());
                }
            }
        }
    }

    fn hex_digit(&mut self) -> Option<u8> {
        let character = self.peek()?;
        let digit = character.to_digit(16)?;
        self.index = self.index.saturating_add(character.len_utf8());
        u8::try_from(digit).ok()
    }
}

fn is_delimiter(character: char, in_bracket: bool) -> bool {
    matches!(
        character,
        '(' | ')'
            | '<'
            | '>'
            | '='
            | '!'
            | '&'
            | '|'
            | '^'
            | '~'
            | '"'
            | '\''
            | '#'
            | '{'
            | '}'
            | ','
            | '*'
            | '%'
            | '+'
            | '['
            | ']'
    ) || (in_bracket && character == ':')
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    text: &'a str,
    tokens: &'a [Token],
    index: usize,
    end: Token,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str, tokens: &'a [Token]) -> Self {
        Self {
            text,
            tokens,
            index: 0,
            end: Token {
                kind: Kind::Word(String::new()),
                start: text.len(),
                end: text.len(),
            },
            depth: 0,
        }
    }

    fn parse(&mut self) -> Result<Expr, FilterError> {
        let expr = self.parse_or()?;
        match self.peek() {
            token if self.is_finished(token) => Ok(expr),
            token => Err(FilterError::at(
                token,
                "unexpected token in the display filter",
            )),
        }
    }

    fn is_finished(&self, token: &Token) -> bool {
        token.start == self.end.start && token.end == self.end.end
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.index).unwrap_or(&self.end)
    }

    fn next(&mut self) -> &Token {
        let index = self.index;
        match self.tokens.get(index) {
            Some(token) => {
                self.index = index.saturating_add(1);
                token
            }
            None => &self.end,
        }
    }

    fn eat(&mut self, kind: Kind) -> bool {
        if self.peek().kind == kind {
            self.index = self.index.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn eat_word(&mut self, word: &str) -> bool {
        let matched = matches!(&self.peek().kind, Kind::Word(text) if text == word);
        if matched {
            self.index = self.index.saturating_add(1);
        }
        matched
    }

    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        let mut expr = self.parse_xor()?;
        let mut links = 0_usize;
        loop {
            let operator = self.peek().clone();
            if !(self.eat(Kind::Or) || self.eat_word("or")) {
                break;
            }
            links = links.saturating_add(1);
            if links > MAX_EXPRESSION_DEPTH {
                return Err(self.too_deep(&operator));
            }
            let right = self.parse_xor()?;
            expr = Expr::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_xor(&mut self) -> Result<Expr, FilterError> {
        let mut expr = self.parse_and()?;
        let mut links = 0_usize;
        loop {
            let operator = self.peek().clone();
            if !(self.eat(Kind::Xor) || self.eat_word("xor")) {
                break;
            }
            links = links.saturating_add(1);
            if links > MAX_EXPRESSION_DEPTH {
                return Err(self.too_deep(&operator));
            }
            let right = self.parse_and()?;
            expr = Expr::Xor(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        let mut expr = self.parse_not()?;
        let mut links = 0_usize;
        loop {
            let operator = self.peek().clone();
            if !(self.eat(Kind::And) || self.eat_word("and")) {
                break;
            }
            links = links.saturating_add(1);
            if links > MAX_EXPRESSION_DEPTH {
                return Err(self.too_deep(&operator));
            }
            let right = self.parse_not()?;
            expr = Expr::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_not(&mut self) -> Result<Expr, FilterError> {
        if self.eat(Kind::Not) || self.eat_word("not") {
            self.enter()?;
            let inner = self.parse_not();
            self.leave();
            return Ok(Expr::Not(Box::new(inner?)));
        }
        self.parse_relation()
    }

    fn parse_relation(&mut self) -> Result<Expr, FilterError> {
        if self.eat(Kind::LeftParen) {
            self.enter()?;
            let inner = self.parse_or();
            self.leave();
            let inner = inner?;
            if !self.eat(Kind::RightParen) {
                let token = self.peek().clone();
                return Err(FilterError::at(&token, "a closing parenthesis is missing"));
            }
            return Ok(inner);
        }
        let mut left = self.parse_operand(false)?;
        if let Some(mut operator) = self.take_comparison_operator() {
            let mut expr: Option<Expr> = None;
            let mut links = 0_usize;
            loop {
                links = links.saturating_add(1);
                if links > MAX_EXPRESSION_DEPTH {
                    let token = self.peek().clone();
                    return Err(self.too_deep(&token));
                }
                let right = self.parse_operand(true)?;
                let comparison = Expr::Compare {
                    left,
                    operator,
                    right: right.clone(),
                };
                expr = Some(match expr {
                    None => comparison,
                    Some(previous) => Expr::And(Box::new(previous), Box::new(comparison)),
                });
                left = right;
                match self.take_comparison_operator() {
                    Some(next) => operator = next,
                    None => break,
                }
            }
            return expr.ok_or_else(|| {
                FilterError::at_end(self.text.len(), "unexpected end of the display filter")
            });
        }
        if self.eat_word("contains") {
            let right = self.parse_operand(true)?;
            return Ok(Expr::Contains { left, right });
        }
        if self.eat(Kind::Tilde) || self.eat_word("matches") {
            let token = self.next().clone();
            let pattern_token = match &token.kind {
                Kind::Quoted(bytes) => bytes.clone(),
                _ => {
                    return Err(FilterError::at(
                        &token,
                        "matches requires a double quoted string on the right side",
                    ));
                }
            };
            let pattern = compile_regex(&pattern_token, &token)?;
            return Ok(Expr::Matches { left, pattern });
        }
        if self.eat_word("in") {
            return self.parse_in(left);
        }
        match left.kind {
            OperandKind::Field { field, layer } => Ok(Expr::Field { field, layer }),
            OperandKind::Protocol { protocol, layer } => Ok(Expr::Protocol { protocol, layer }),
            _ => Ok(Expr::Truthy(left)),
        }
    }

    fn take_comparison_operator(&mut self) -> Option<CompareOp> {
        let operator = comparison_operator(&self.peek().kind)?;
        self.index = self.index.saturating_add(1);
        Some(operator)
    }

    fn parse_in(&mut self, left: Operand) -> Result<Expr, FilterError> {
        let (field, layer) = match &left.kind {
            OperandKind::Field { field, layer } => (*field, *layer),
            _ => {
                return Err(FilterError::at_span(
                    left.start,
                    left.end,
                    "only a field may be tested for membership in a set".to_string(),
                ));
            }
        };
        let brace = self.next().clone();
        if !matches!(brace.kind, Kind::LeftBrace) {
            return Err(FilterError::at(&brace, "expected '{' after 'in'"));
        }
        if matches!(self.peek().kind, Kind::RightBrace) {
            return Err(FilterError::at(self.peek(), "an empty set is not allowed"));
        }
        let mut members = Vec::new();
        loop {
            let member = self.parse_set_member(field)?;
            members.push(member);
            let separator = self.next().clone();
            match separator.kind {
                Kind::Comma => {
                    if matches!(self.peek().kind, Kind::RightBrace) {
                        return Err(FilterError::at(
                            self.peek(),
                            "a set element is required after ','",
                        ));
                    }
                }
                Kind::RightBrace => break,
                _ if self.is_finished(&separator) => {
                    return Err(FilterError::at_end(
                        separator.start,
                        "unexpected end of the display filter",
                    ));
                }
                _ => {
                    return Err(FilterError::at(&separator, "expected ',' or '}' in a set"));
                }
            }
        }
        Ok(Expr::In {
            field,
            layer,
            members,
        })
    }

    fn parse_set_member(&mut self, field: &'static FieldDef) -> Result<InMember, FilterError> {
        let token = self.peek().clone();
        if self.is_finished(&token)
            || matches!(token.kind, Kind::RightBrace | Kind::Comma | Kind::RangeDots)
        {
            return Err(FilterError::at(&token, "a set element is required"));
        }
        if let Kind::Word(text) = &token.kind
            && matches!(field.field_type, FieldType::Ipv4 | FieldType::Ipv6)
            && let Some((address, prefix)) = text.split_once('/')
        {
            self.next();
            let member = cidr_member(field, address, prefix, &token)?;
            if self.eat_range() {
                let InMember::Cidr { network, .. } = member else {
                    return Err(FilterError::at(&token, "a CIDR element is required"));
                };
                let start = Operand::new(
                    OperandKind::Literal {
                        ty: network.ty(),
                        literal: network,
                    },
                    token.start,
                    token.end,
                );
                let end = self.parse_set_endpoint(field)?;
                return Ok(InMember::Range(start, end));
            }
            return Ok(member);
        }
        let start = self.parse_set_endpoint(field)?;
        if self.eat_range() {
            let end = self.parse_set_endpoint(field)?;
            return Ok(InMember::Range(start, end));
        }
        Ok(InMember::Value(start))
    }

    fn parse_set_endpoint(&mut self, field: &'static FieldDef) -> Result<Operand, FilterError> {
        let token = self.peek().clone();
        if let Kind::Word(text) = &token.kind
            && matches!(field.field_type, FieldType::Ipv4 | FieldType::Ipv6)
            && let Some((address, prefix)) = text.split_once('/')
        {
            self.next();
            return cidr_member(field, address, prefix, &token).map(|member| match member {
                InMember::Cidr { network, .. } => Operand::new(
                    OperandKind::Literal {
                        ty: network.ty(),
                        literal: network,
                    },
                    token.start,
                    token.end,
                ),
                _ => Operand::new(
                    OperandKind::TokenLiteral(TokenLiteral::Word(text.clone())),
                    token.start,
                    token.end,
                ),
            });
        }
        self.parse_operand(true)
    }

    fn eat_range(&mut self) -> bool {
        if matches!(self.peek().kind, Kind::RangeDots) {
            self.index = self.index.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn parse_operand(&mut self, literal_ok: bool) -> Result<Operand, FilterError> {
        self.enter_operand()?;
        let result = self.parse_operand_inner(literal_ok);
        self.leave();
        result
    }

    fn parse_operand_inner(&mut self, literal_ok: bool) -> Result<Operand, FilterError> {
        let mut operand = self.parse_additive(literal_ok)?;
        let mut links = 0_usize;
        while matches!(self.peek().kind, Kind::Ampersand) {
            let operator = self.next().clone();
            links = links.saturating_add(1);
            if links > MAX_EXPRESSION_DEPTH {
                return Err(self.too_deep(&operator));
            }
            let right = self.parse_additive(true)?;
            operand = build_binary(operand, ArithOp::BitwiseAnd, right);
        }
        Ok(operand)
    }

    fn parse_additive(&mut self, literal_ok: bool) -> Result<Operand, FilterError> {
        let mut operand = self.parse_multiplicative(literal_ok)?;
        let mut links = 0_usize;
        loop {
            let token = self.peek().clone();
            let operator = match self.peek().kind {
                Kind::Plus => ArithOp::Add,
                Kind::Minus => ArithOp::Subtract,
                _ => break,
            };
            self.next();
            links = links.saturating_add(1);
            if links > MAX_EXPRESSION_DEPTH {
                return Err(self.too_deep(&token));
            }
            let right = self.parse_multiplicative(true)?;
            operand = build_binary(operand, operator, right);
        }
        Ok(operand)
    }

    fn parse_multiplicative(&mut self, literal_ok: bool) -> Result<Operand, FilterError> {
        let mut operand = self.parse_unary(literal_ok)?;
        let mut links = 0_usize;
        loop {
            let token = self.peek().clone();
            let operator = match self.peek().kind {
                Kind::Star => ArithOp::Multiply,
                Kind::Slash => ArithOp::Divide,
                Kind::Percent => ArithOp::Modulo,
                _ => break,
            };
            self.next();
            links = links.saturating_add(1);
            if links > MAX_EXPRESSION_DEPTH {
                return Err(self.too_deep(&token));
            }
            let right = self.parse_unary(true)?;
            operand = build_binary(operand, operator, right);
        }
        Ok(operand)
    }

    fn parse_unary(&mut self, literal_ok: bool) -> Result<Operand, FilterError> {
        let token = self.peek().clone();
        if self.eat(Kind::Minus) {
            if self.depth >= MAX_EXPRESSION_DEPTH {
                return Err(self.too_deep(&token));
            }
            self.depth = self.depth.saturating_add(1);
            let inner = self.parse_unary(true);
            self.depth = self.depth.saturating_sub(1);
            let inner = inner?;
            let end = inner.end;
            return Ok(Operand::new(
                OperandKind::Negate(Box::new(inner)),
                token.start,
                end,
            ));
        }
        if self.eat(Kind::Plus) {
            if self.depth >= MAX_EXPRESSION_DEPTH {
                return Err(self.too_deep(&token));
            }
            self.depth = self.depth.saturating_add(1);
            let inner = self.parse_unary(literal_ok);
            self.depth = self.depth.saturating_sub(1);
            let inner = inner?;
            let end = inner.end;
            return Ok(Operand::new(
                OperandKind::UnaryPlus(Box::new(inner)),
                token.start,
                end,
            ));
        }
        self.parse_postfix(literal_ok)
    }

    fn parse_postfix(&mut self, literal_ok: bool) -> Result<Operand, FilterError> {
        let mut operand = self.parse_primary(literal_ok)?;
        let mut slices = 0_usize;
        while matches!(self.peek().kind, Kind::LeftBracket) {
            slices = slices.saturating_add(1);
            if slices > MAX_EXPRESSION_DEPTH {
                let token = self.peek().clone();
                return Err(self.too_deep(&token));
            }
            let slice = self.parse_slice()?;
            let start = operand.start;
            let end = self.peek().start;
            operand = Operand::new(
                OperandKind::Slice {
                    inner: Box::new(operand),
                    slice,
                },
                start,
                end,
            );
        }
        Ok(operand)
    }

    fn parse_primary(&mut self, literal_ok: bool) -> Result<Operand, FilterError> {
        let token = self.next().clone();
        match &token.kind {
            Kind::Word(name) => {
                if matches!(self.peek().kind, Kind::LeftParen) {
                    if let Some(function) = function_by_name(name) {
                        return self.parse_function(function, token);
                    }
                    return Err(FilterError::at(
                        &token,
                        format!("function {name:?} does not exist"),
                    ));
                }
                let layer = self.take_layer();
                if let Some(field) = fields::registry().field(name) {
                    return Ok(Operand::new(
                        OperandKind::Field { field, layer },
                        token.start,
                        token.end,
                    ));
                }
                if let Some(protocol) = protocol_by_name(name) {
                    return Ok(Operand::new(
                        OperandKind::Protocol { protocol, layer },
                        token.start,
                        token.end,
                    ));
                }
                if !literal_ok && !is_literal_word(name) {
                    return Err(FilterError::at(
                        &token,
                        format!("\"{name}\" is not a registered protocol or field"),
                    ));
                }
                Ok(Operand::new(
                    OperandKind::TokenLiteral(TokenLiteral::Word(name.clone())),
                    token.start,
                    token.end,
                ))
            }
            Kind::Quoted(bytes) => Ok(Operand::new(
                OperandKind::TokenLiteral(TokenLiteral::Quoted(bytes.clone())),
                token.start,
                token.end,
            )),
            _ if self.is_finished(&token) => Err(FilterError::at_end(
                token.start,
                "unexpected end of the display filter",
            )),
            _ => Err(FilterError::at(
                &token,
                "unexpected token in the display filter",
            )),
        }
    }

    fn parse_function(&mut self, function: Function, name: Token) -> Result<Operand, FilterError> {
        let open = self.next().clone();
        if !matches!(open.kind, Kind::LeftParen) {
            return Err(FilterError::at(&open, "expected '(' after a function name"));
        }
        if matches!(self.peek().kind, Kind::RightParen) {
            return Err(FilterError::at(
                self.peek(),
                "a function needs one argument",
            ));
        }
        let arg = self.parse_operand(true)?;
        if self.eat(Kind::Comma) {
            let extra = self.next().clone();
            return Err(FilterError::at(
                &extra,
                format!("function {:?} can only accept 1 argument", function),
            ));
        }
        let close = self.next().clone();
        if !matches!(close.kind, Kind::RightParen) {
            return Err(FilterError::at(&close, "a closing parenthesis is missing"));
        }
        Ok(Operand::new(
            OperandKind::Function {
                function,
                arg: Box::new(arg),
                ty: Type::Untyped,
            },
            name.start,
            close.end,
        ))
    }

    fn parse_slice(&mut self) -> Result<Slice, FilterError> {
        let open = self.next().clone();
        let first = self.parse_slice_bound()?;
        let mut start = first;
        let mut length = None;
        let mut colon = false;
        if self.eat(Kind::Colon) {
            colon = true;
            let second = self.parse_slice_bound()?;
            length = second;
        } else if let Some(value) = first {
            start = Some(value);
            length = Some(1);
        }
        if first.is_none() && !colon {
            return Err(FilterError::at(&open, "an empty range is not allowed"));
        }
        let close = self.next().clone();
        if !matches!(close.kind, Kind::RightBracket) {
            return Err(FilterError::at(&close, "a closing bracket is missing"));
        }
        if let Some(length) = length
            && length <= 0
        {
            return Err(FilterError::at_span(
                open.start,
                close.end,
                format!("range length {length} is not positive"),
            ));
        }
        Ok(Slice { start, length })
    }

    fn parse_slice_bound(&mut self) -> Result<Option<i64>, FilterError> {
        let token = self.peek().clone();
        if matches!(token.kind, Kind::Colon | Kind::RightBracket) {
            return Ok(None);
        }
        let negative = self.eat(Kind::Minus);
        if !negative {
            let _ = self.eat(Kind::Plus);
        }
        let bound = self.peek().clone();
        let word = match &bound.kind {
            Kind::Word(word) => word.clone(),
            _ => {
                return Err(FilterError::at(
                    &bound,
                    "an integer range bound is required",
                ));
            }
        };
        let value = parse_integer(&word)
            .and_then(|value| {
                if negative {
                    value.checked_neg()
                } else {
                    Some(value)
                }
            })
            .and_then(|value| i64::try_from(value).ok())
            .filter(|value| *value >= i64::from(i32::MIN) && *value <= i64::from(i32::MAX))
            .ok_or_else(|| {
                FilterError::at(
                    &bound,
                    format!("{word:?} is not a valid integer range bound"),
                )
            })?;
        self.next();
        Ok(Some(value))
    }

    fn take_layer(&mut self) -> Option<u64> {
        let layer = match &self.peek().kind {
            Kind::Hash(layer) => *layer,
            _ => return None,
        };
        self.index = self.index.saturating_add(1);
        Some(layer)
    }

    fn too_deep(&self, token: &Token) -> FilterError {
        FilterError::at_span(
            token.start,
            token.end,
            "the display filter is nested too deeply".to_string(),
        )
    }

    fn enter(&mut self) -> Result<(), FilterError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_EXPRESSION_DEPTH {
            return Err(FilterError::new(
                0,
                None,
                "the display filter is nested too deeply".to_string(),
            ));
        }
        Ok(())
    }

    fn enter_operand(&mut self) -> Result<(), FilterError> {
        self.enter()
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

fn build_binary(left: Operand, operator: ArithOp, right: Operand) -> Operand {
    let start = left.start;
    let end = right.end;
    Operand::new(
        OperandKind::Binary {
            operator,
            left: Box::new(left),
            right: Box::new(right),
            ty: Type::Untyped,
        },
        start,
        end,
    )
}

fn is_literal_word(text: &str) -> bool {
    parse_integer(text).is_some() || text.parse::<f64>().is_ok() || is_numeric_token(text)
}

fn compile_regex(pattern: &[u8], token: &Token) -> Result<Pattern, FilterError> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(FilterError::at(
            token,
            format!("the regular expression exceeds {MAX_PATTERN_BYTES} bytes"),
        ));
    }
    let source = normalize_pattern(pattern);
    let regex = RegexBuilder::new(&source)
        .case_insensitive(true)
        .unicode(false)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|error| FilterError::at(token, format!("regex compilation error: {error}")))?;
    Ok(Pattern { source, regex })
}

/// Translate the PCRE2 escapes the Rust regex crate lacks into equivalents
/// and express non-ASCII pattern bytes as `\xNN`, matching PCRE2's byte
/// mode. `\Q...\E` becomes escaped literal text.
fn normalize_pattern(pattern: &[u8]) -> String {
    let mut output = String::new();
    let mut index = 0_usize;
    let mut in_class = false;
    while let Some(&byte) = pattern.get(index) {
        if byte == b'\\' {
            let Some(&next) = pattern.get(index.saturating_add(1)) else {
                output.push('\\');
                break;
            };
            match next {
                b'Q' => {
                    let start = index.saturating_add(2);
                    let mut end = start;
                    while end < pattern.len() {
                        if pattern.get(end) == Some(&b'\\')
                            && pattern.get(end.saturating_add(1)) == Some(&b'E')
                        {
                            break;
                        }
                        end = end.saturating_add(1);
                    }
                    push_quoted(&mut output, pattern.get(start..end).unwrap_or_default());
                    index = if end < pattern.len() {
                        end.saturating_add(2)
                    } else {
                        pattern.len()
                    };
                    continue;
                }
                b'E' => {
                    index = index.saturating_add(2);
                    continue;
                }
                b'Z' if !in_class => {
                    output.push_str(r"(?:\n?\z)");
                    index = index.saturating_add(2);
                    continue;
                }
                b'G' if !in_class => {
                    output.push_str("\\A");
                    index = index.saturating_add(2);
                    continue;
                }
                b'h' => {
                    if in_class {
                        output.push_str(" \t");
                    } else {
                        output.push_str("[ \t]");
                    }
                    index = index.saturating_add(2);
                    continue;
                }
                b'H' if !in_class => {
                    output.push_str("[^ \t]");
                    index = index.saturating_add(2);
                    continue;
                }
                b'V' if !in_class => {
                    output.push_str("[^\\n\\r\\f\\x0b]");
                    index = index.saturating_add(2);
                    continue;
                }
                b'N' if !in_class => {
                    output.push_str("[^\\n]");
                    index = index.saturating_add(2);
                    continue;
                }
                _ => {
                    output.push('\\');
                    output.push(char::from(next));
                    index = index.saturating_add(2);
                    continue;
                }
            }
        }
        if byte == b'[' && !in_class {
            in_class = true;
            output.push('[');
        } else if byte == b']' && in_class {
            in_class = false;
            output.push(']');
        } else if byte.is_ascii() {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("\\x{byte:02x}"));
        }
        index = index.saturating_add(1);
    }
    output
}

fn push_quoted(output: &mut String, bytes: &[u8]) {
    for &byte in bytes {
        if byte.is_ascii() {
            let character = char::from(byte);
            let mut encoded = [0_u8; 4];
            output.push_str(&regex::escape(character.encode_utf8(&mut encoded)));
        } else {
            output.push_str(&format!("\\x{byte:02x}"));
        }
    }
}

fn expression_depth(root: &Expr) -> usize {
    let mut deepest = 0;
    let mut pending = vec![(NodeRef::Expr(root), 1_usize)];
    while let Some((reference, depth)) = pending.pop() {
        deepest = deepest.max(depth);
        match reference {
            NodeRef::Expr(expr) => match expr {
                Expr::Not(inner) => pending.push((NodeRef::Expr(inner), depth.saturating_add(1))),
                Expr::And(left, right) | Expr::Or(left, right) | Expr::Xor(left, right) => {
                    pending.push((NodeRef::Expr(left), depth.saturating_add(1)));
                    pending.push((NodeRef::Expr(right), depth.saturating_add(1)));
                }
                Expr::Truthy(operand) => {
                    pending.push((NodeRef::Operand(operand), depth.saturating_add(1)));
                }
                Expr::Compare { left, right, .. } | Expr::Contains { left, right } => {
                    pending.push((NodeRef::Operand(left), depth.saturating_add(1)));
                    pending.push((NodeRef::Operand(right), depth.saturating_add(1)));
                }
                Expr::Matches { left, .. } => {
                    pending.push((NodeRef::Operand(left), depth.saturating_add(1)));
                }
                Expr::In { members, .. } => {
                    for member in members {
                        match member {
                            InMember::Value(operand) => {
                                pending.push((NodeRef::Operand(operand), depth.saturating_add(1)));
                            }
                            InMember::Range(start, end) => {
                                pending.push((NodeRef::Operand(start), depth.saturating_add(1)));
                                pending.push((NodeRef::Operand(end), depth.saturating_add(1)));
                            }
                            InMember::Cidr { .. } => {}
                        }
                    }
                }
                Expr::Protocol { .. } | Expr::Field { .. } => {}
            },
            NodeRef::Operand(operand) => match &operand.kind {
                OperandKind::Slice { inner, .. }
                | OperandKind::Negate(inner)
                | OperandKind::UnaryPlus(inner) => {
                    pending.push((NodeRef::Operand(inner), depth.saturating_add(1)));
                }
                OperandKind::Function { arg, .. } => {
                    pending.push((NodeRef::Operand(arg), depth.saturating_add(1)));
                }
                OperandKind::Binary { left, right, .. } => {
                    pending.push((NodeRef::Operand(left), depth.saturating_add(1)));
                    pending.push((NodeRef::Operand(right), depth.saturating_add(1)));
                }
                _ => {}
            },
        }
    }
    deepest
}
// ---------------------------------------------------------------------------
// Literal conversion
// ---------------------------------------------------------------------------

fn cidr_member(
    field: &FieldDef,
    address: &str,
    prefix: &str,
    token: &Token,
) -> Result<InMember, FilterError> {
    let (network, maximum) = match field.field_type {
        FieldType::Ipv4 => (parse_ipv4(address).map(Literal::Ipv4), 32_u8),
        FieldType::Ipv6 => (parse_ipv6(address).map(Literal::Ipv6), 128_u8),
        _ => {
            return Err(FilterError::at(
                token,
                "a CIDR prefix is only valid for IPv4 or IPv6 fields",
            ));
        }
    };
    let network = network.ok_or_else(|| {
        FilterError::at(token, format!("{address:?} is not a valid CIDR address"))
    })?;
    let prefix = prefix
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then_some(prefix)
        .and_then(|prefix| prefix.parse::<u8>().ok())
        .filter(|prefix| *prefix <= maximum)
        .ok_or_else(|| {
            FilterError::at(
                token,
                format!("a CIDR prefix must be between 0 and {maximum}"),
            )
        })?;
    Ok(InMember::Cidr { network, prefix })
}

fn convert_word(ty: Type, text: &str, token: &Token) -> Result<Literal, FilterError> {
    if ty == Type::Double {
        return double_literal(text, token);
    }
    let field_type = match ty {
        Type::Uint(_) | Type::Int(_) => ty.field_type(),
        Type::Boolean => Some(FieldType::Boolean),
        Type::String => Some(FieldType::String),
        Type::Bytes => Some(FieldType::Bytes),
        Type::Ethernet => Some(FieldType::Ethernet),
        Type::Eui64 => Some(FieldType::Eui64),
        Type::Ipv4 => Some(FieldType::Ipv4),
        Type::Ipv6 => Some(FieldType::Ipv6),
        Type::Time => Some(FieldType::AbsoluteTime),
        Type::Relative => Some(FieldType::RelativeTime),
        Type::Double | Type::Protocol | Type::Untyped => None,
    };
    let Some(ty) = field_type else {
        return Err(FilterError::at(
            token,
            format!("{text:?} cannot be converted to {}", ty.name()),
        ));
    };
    match ty {
        FieldType::Uint8 => integer_literal(text, 8, false, token),
        FieldType::Uint16 => integer_literal(text, 16, false, token),
        FieldType::Uint24 => integer_literal(text, 24, false, token),
        FieldType::Uint32 | FieldType::FrameNumber => integer_literal(text, 32, false, token),
        FieldType::Uint64 => integer_literal(text, 64, false, token),
        FieldType::Int8 => integer_literal(text, 8, true, token),
        FieldType::Int16 => integer_literal(text, 16, true, token),
        FieldType::Int32 => integer_literal(text, 32, true, token),
        FieldType::Int64 => integer_literal(text, 64, true, token),
        FieldType::Boolean => boolean_literal(text).map(Literal::Boolean).ok_or_else(|| {
            FilterError::at(
                token,
                format!("{text:?} is not a valid boolean value; use Set or Not set"),
            )
        }),
        FieldType::String | FieldType::StringZ | FieldType::StringzPad | FieldType::Oid => {
            string_literal(text, token)
        }
        FieldType::Double => double_literal(text, token),
        FieldType::Ethernet => parse_ethernet(text)
            .map(Literal::Ethernet)
            .ok_or_else(|| FilterError::at(token, format!("{text:?} is not a valid MAC address"))),
        FieldType::Eui64 => eui64_literal(text, token),
        FieldType::Ipv4 => parse_ipv4(text)
            .map(Literal::Ipv4)
            .ok_or_else(|| FilterError::at(token, format!("{text:?} is not a valid IPv4 address"))),
        FieldType::Ipv6 => parse_ipv6(text)
            .map(Literal::Ipv6)
            .ok_or_else(|| FilterError::at(token, format!("{text:?} is not a valid IPv6 address"))),
        FieldType::Bytes => bytes_literal(text)
            .map(|bytes| Literal::Bytes(bytes.into()))
            .ok_or_else(|| FilterError::at(token, format!("{text:?} is not a valid byte value"))),
        FieldType::AbsoluteTime => {
            let (seconds, nanos) = parse_time_text(text).ok_or_else(|| {
                FilterError::at(token, format!("{text:?} is not a valid time value"))
            })?;
            Ok(Literal::Time { seconds, nanos })
        }
        FieldType::RelativeTime => relative_seconds_literal(text, token),
        FieldType::None => Err(FilterError::at(
            token,
            "a label cannot be compared".to_string(),
        )),
    }
}

fn convert_quoted(ty: Type, bytes: &[u8], token: &Token) -> Result<Literal, FilterError> {
    if ty == Type::Double {
        return double_literal(
            std::str::from_utf8(bytes).map_err(|_| {
                FilterError::at(token, "a quoted string is not valid UTF-8 for this field")
            })?,
            token,
        );
    }
    let field_type = match ty {
        Type::Uint(_) | Type::Int(_) => ty.field_type(),
        Type::Boolean => Some(FieldType::Boolean),
        Type::String => Some(FieldType::String),
        Type::Bytes => Some(FieldType::Bytes),
        Type::Ethernet => Some(FieldType::Ethernet),
        Type::Eui64 => Some(FieldType::Eui64),
        Type::Ipv4 => Some(FieldType::Ipv4),
        Type::Ipv6 => Some(FieldType::Ipv6),
        Type::Time => Some(FieldType::AbsoluteTime),
        Type::Relative => Some(FieldType::RelativeTime),
        Type::Double | Type::Protocol | Type::Untyped => None,
    };
    let Some(ty) = field_type else {
        return Err(FilterError::at(
            token,
            format!("a quoted string cannot be converted to {}", ty.name()),
        ));
    };
    let text = || {
        std::str::from_utf8(bytes).map_err(|_| {
            FilterError::at(token, "a quoted string is not valid UTF-8 for this field")
        })
    };
    match ty {
        FieldType::Bytes => Ok(Literal::Bytes(bytes.into())),
        FieldType::String | FieldType::StringZ | FieldType::StringzPad | FieldType::Oid => {
            Ok(Literal::String(
                std::str::from_utf8(bytes)
                    .map_err(|_| {
                        FilterError::at(token, "a quoted string is not valid UTF-8 for this field")
                    })?
                    .to_string(),
            ))
        }
        FieldType::Double => double_literal(
            std::str::from_utf8(bytes).map_err(|_| {
                FilterError::at(token, "a quoted string is not valid UTF-8 for this field")
            })?,
            token,
        ),
        FieldType::Boolean => {
            let text = text()?;
            if text.eq_ignore_ascii_case("set") {
                Ok(Literal::Boolean(true))
            } else if text.eq_ignore_ascii_case("not set") {
                Ok(Literal::Boolean(false))
            } else {
                Err(FilterError::at(
                    token,
                    format!("{text:?} is not a boolean value string; use Set or Not set"),
                ))
            }
        }
        FieldType::AbsoluteTime | FieldType::RelativeTime => {
            let text = text()?;
            let (seconds, nanos) = parse_time_text(text).ok_or_else(|| {
                FilterError::at(token, format!("{text:?} is not a valid date and time"))
            })?;
            Ok(Literal::Time { seconds, nanos })
        }
        _ => Err(FilterError::at(
            token,
            format!(
                "a quoted string cannot be converted to {}",
                ty.abbreviation()
            ),
        )),
    }
}

fn double_literal(text: &str, token: &Token) -> Result<Literal, FilterError> {
    text.parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
        .map(Literal::Double)
        .ok_or_else(|| FilterError::at(token, format!("{text:?} is not a valid number")))
}

/// Parse a relative-time operand as decimal seconds and scale it to the
/// nanoseconds the field stores, so `tcp.analysis.initial_rtt > 0.0005`
/// compares in fractional seconds.
fn relative_seconds_literal(text: &str, token: &Token) -> Result<Literal, FilterError> {
    parse_relative_seconds(text)
        .map(Literal::Integer)
        .ok_or_else(|| FilterError::at(token, format!("{text:?} is not a valid relative time")))
}

/// Parse decimal seconds as exactly the nanoseconds a relative field stores.
///
/// Accepts an optional sign, an optional whole part and up to nine fractional
/// digits. Other forms, such as an exponent, are not relative seconds.
fn parse_relative_seconds(text: &str) -> Option<i128> {
    let (negative, body) = match text.strip_prefix('-') {
        Some(body) => (true, body),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if body.is_empty() {
        return None;
    }
    let (whole, fraction) = body.split_once('.').unwrap_or((body, ""));
    if fraction.len() > 9
        || (!whole.is_empty() && !whole.chars().all(|character| character.is_ascii_digit()))
        || !fraction.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    let whole: i128 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut fractional: i128 = 0;
    for character in fraction.chars() {
        fractional = fractional * 10 + i128::from(character.to_digit(10).unwrap_or(0));
    }
    for _ in fraction.len()..9 {
        fractional *= 10;
    }
    let mut nanos = whole
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(fractional))?;
    if negative {
        nanos = -nanos;
    }
    Some(nanos)
}

fn integer_literal(
    text: &str,
    bits: u32,
    signed: bool,
    token: &Token,
) -> Result<Literal, FilterError> {
    let value = parse_integer(text)
        .ok_or_else(|| FilterError::at(token, format!("{text:?} is not a valid integer")))?;
    let shift = bits.min(64);
    let magnitude = 1_i128 << shift;
    if signed {
        let minimum = -(magnitude >> 1);
        let maximum = (magnitude >> 1) - 1;
        if value < minimum || value > maximum {
            return Err(FilterError::at(
                token,
                format!("{text:?} does not fit this signed {bits}-bit field"),
            ));
        }
    } else {
        let maximum = magnitude - 1;
        let magnitude_limit = u128::try_from(maximum).unwrap_or(u128::MAX);
        if value > maximum || (value < 0 && value.unsigned_abs() > magnitude_limit) {
            return Err(FilterError::at(
                token,
                format!("{text:?} is too large for this {bits}-bit field; maximum {maximum}"),
            ));
        }
    }
    Ok(Literal::Integer(value))
}

fn parse_integer(text: &str) -> Option<i128> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if rest.is_empty() {
        return None;
    }
    let (base, digits) =
        if let Some(digits) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            (16, digits)
        } else if let Some(digits) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
            (2, digits)
        } else if rest.len() > 1 && rest.starts_with('0') {
            (8, rest.get(1..).unwrap_or_default())
        } else {
            (10, rest)
        };
    if digits.is_empty() {
        return None;
    }
    let magnitude = i128::from_str_radix(digits, base).ok()?;
    if negative {
        magnitude.checked_neg()
    } else {
        Some(magnitude)
    }
}

/// Unquoted `FT_STRING` literal rules.
///
/// Numbers, operator keywords, protocols and fields are separate tokens and
/// cannot be converted to a string. Plain identifiers, address-looking words
/// and the boolean value strings stay strings.
fn is_numeric_token(text: &str) -> bool {
    let rest = text
        .strip_prefix('-')
        .or_else(|| text.strip_prefix('+'))
        .unwrap_or(text);
    if rest.len() > 1 && rest.starts_with('0') {
        if let Some((mantissa, _)) = rest.split_once(['e', 'E'])
            && !rest.contains('.')
            && !mantissa.is_empty()
            && mantissa.bytes().all(|byte| byte.is_ascii_digit())
        {
            // `0e1`, `00e1` and `09e1` stay identifiers, not numbers.
            return false;
        }
        if !rest.contains('.') && rest.bytes().all(|byte| byte.is_ascii_digit()) {
            // Leading-zero integers are octal; 8 and 9 make the token an
            // identifier (`08`, `018`) rather than a number.
            return rest.bytes().all(|byte| (b'0'..=b'7').contains(&byte));
        }
    }
    parse_integer(text).is_some() || text.parse::<f64>().is_ok()
}

fn string_literal(text: &str, token: &Token) -> Result<Literal, FilterError> {
    if text.starts_with('-') {
        return Err(FilterError::at(
            token,
            "a string literal cannot be negated".to_string(),
        ));
    }
    let value = text.strip_prefix('+').unwrap_or(text);
    if value.is_empty() {
        return Err(FilterError::at(token, "\"+\" needs an operand".to_string()));
    }
    if is_numeric_token(text) {
        return Err(FilterError::at(
            token,
            format!("{text:?} is a number and cannot be converted to a string"),
        ));
    }
    if is_operator_word(text) {
        return Err(FilterError::at(
            token,
            format!("{text:?} is an operator and cannot be used as a string"),
        ));
    }
    if protocol_by_name(value).is_some() || fields::registry().field(value).is_some() {
        return Err(FilterError::at(
            token,
            format!("{value:?} is a protocol or field and is not compatible with a string"),
        ));
    }
    Ok(Literal::String(value.to_string()))
}

fn is_operator_word(text: &str) -> bool {
    matches!(
        text,
        "and"
            | "or"
            | "xor"
            | "not"
            | "eq"
            | "ne"
            | "gt"
            | "lt"
            | "ge"
            | "le"
            | "any_eq"
            | "all_eq"
            | "any_ne"
            | "all_ne"
            | "contains"
            | "in"
            | "matches"
    )
}

fn boolean_literal(text: &str) -> Option<bool> {
    if text.starts_with('-') {
        return None;
    }
    if text.eq_ignore_ascii_case("true") || text.eq_ignore_ascii_case("set") {
        return Some(true);
    }
    if text.eq_ignore_ascii_case("false") || text.eq_ignore_ascii_case("not set") {
        return Some(false);
    }
    parse_integer(text).map(|value| value != 0)
}

fn parse_mac<const N: usize>(text: &str) -> Option<[u8; N]> {
    let separator = byte_separator(text)?;
    let mut bytes = [0_u8; N];
    let mut count = 0;
    for group in text.split(separator) {
        if count >= N || group.is_empty() || group.len() > 2 {
            return None;
        }
        let value = u8::from_str_radix(group, 16).ok()?;
        *bytes.get_mut(count)? = value;
        count = count.saturating_add(1);
    }
    (count == N).then_some(bytes)
}

/// Parse dotted EUI64/Ethernet byte groups: one or two hex digits
/// are one byte, four hex digits are two bytes. Any group count is allowed;
/// equality applies the eight-byte EUI64 length check separately.
fn dotted_bytes(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    for group in text.split('.') {
        if group.is_empty() {
            return None;
        }
        if group.len() <= 2 {
            bytes.push(u8::from_str_radix(group, 16).ok()?);
        } else if group.len() == 4 {
            bytes.push(u8::from_str_radix(group.get(..2)?, 16).ok()?);
            bytes.push(u8::from_str_radix(group.get(2..)?, 16).ok()?);
        } else {
            return None;
        }
    }
    (!bytes.is_empty()).then_some(bytes)
}

/// Convert an EUI64 operand to bytes.
///
/// Dotted and colon/hyphen forms use byte groups; a bare integer becomes its
/// eight-byte big-endian value. Equality requires exactly eight bytes, but
/// `contains` accepts any non-empty byte sequence.
fn eui64_bytes(text: &str, token: &Token) -> Result<Vec<u8>, FilterError> {
    if text.contains('.') {
        return dotted_bytes(text).ok_or_else(|| {
            FilterError::at(token, format!("{text:?} is not a valid EUI-64 value"))
        });
    }
    if text.contains(':') || text.contains('-') {
        return bytes_literal(text).ok_or_else(|| {
            FilterError::at(token, format!("{text:?} is not a valid EUI-64 value"))
        });
    }
    let value = parse_integer(text)
        .ok_or_else(|| FilterError::at(token, format!("{text:?} is not a valid EUI-64 value")))?;
    if value < 0 {
        return Err(FilterError::at(token, "an EUI-64 value cannot be negative"));
    }
    let maximum = i128::from(u64::MAX);
    if value > maximum {
        return Err(FilterError::at(
            token,
            format!("{text:?} contains too many bytes to be a valid EUI-64 address"),
        ));
    }
    let value = u64::try_from(value)
        .map_err(|_| FilterError::at(token, format!("{text:?} is not a valid EUI-64 value")))?;
    Ok(value.to_be_bytes().to_vec())
}

fn eui64_literal(text: &str, token: &Token) -> Result<Literal, FilterError> {
    let bytes = eui64_bytes(text, token)?;
    if bytes.len() < 8 {
        return Err(FilterError::at(
            token,
            format!("{text:?} contains too few bytes to be a valid EUI-64 address"),
        ));
    }
    if bytes.len() > 8 {
        return Err(FilterError::at(
            token,
            format!("{text:?} contains too many bytes to be a valid EUI-64 address"),
        ));
    }
    let mut address = [0_u8; 8];
    for (slot, byte) in address.iter_mut().zip(bytes) {
        *slot = byte;
    }
    Ok(Literal::Eui64(address))
}

fn eui64_needle(text: &str, token: &Token) -> Result<Vec<u8>, FilterError> {
    let bytes = eui64_bytes(text, token)?;
    if bytes.len() > 8 {
        return Err(FilterError::at(
            token,
            format!("{text:?} contains too many bytes to be a valid EUI-64 address"),
        ));
    }
    Ok(bytes)
}

/// Convert a `contains` needle for an address-typed field.
///
/// Dotted Ethernet forms go through the address parser; colon/hyphen byte
/// sequences may be partial. Bare numbers, floats and separatorless words
/// are type errors.
fn ethernet_needle(text: &str, token: &Token) -> Result<Vec<u8>, FilterError> {
    let bytes = if text.contains('.') {
        parse_ethernet(text)
            .map(|address| address.to_vec())
            .ok_or_else(|| {
                FilterError::at(token, format!("{text:?} is not a valid Ethernet needle"))
            })?
    } else if text.contains(':') || text.contains('-') {
        bytes_literal(text).ok_or_else(|| {
            FilterError::at(token, format!("{text:?} is not a valid address needle"))
        })?
    } else {
        return Err(FilterError::at(
            token,
            format!("{text:?} is not a valid address needle"),
        ));
    };
    if bytes.len() > 6 {
        return Err(FilterError::at(
            token,
            format!("{text:?} contains too many bytes to be a valid Ethernet address"),
        ));
    }
    Ok(bytes)
}

/// Parse the Ethernet address forms: colon/hyphen byte groups, three 16-bit
/// colon/hyphen groups, three dotted 16-bit groups, or six dotted byte
/// groups.
fn parse_ethernet(text: &str) -> Option<[u8; 6]> {
    if !text.contains('.') {
        if let Some(separator) = byte_separator(text) {
            let groups: Vec<&str> = text.split(separator).collect();
            if groups.len() == 3 && groups.iter().all(|group| group.len() == 4) {
                let mut bytes = [0_u8; 6];
                let mut out = 0;
                for group in groups {
                    let high = u8::from_str_radix(group.get(..2)?, 16).ok()?;
                    let low = u8::from_str_radix(group.get(2..)?, 16).ok()?;
                    *bytes.get_mut(out)? = high;
                    *bytes.get_mut(out.saturating_add(1))? = low;
                    out = out.saturating_add(2);
                }
                return Some(bytes);
            }
        }
        return parse_mac::<6>(text);
    }
    let groups: Vec<&str> = text.split('.').collect();
    let mut bytes = [0_u8; 6];
    let mut out = 0;
    match groups.len() {
        3 => {
            for group in groups {
                if group.len() != 4 {
                    return None;
                }
                let high = u8::from_str_radix(group.get(..2)?, 16).ok()?;
                let low = u8::from_str_radix(group.get(2..)?, 16).ok()?;
                *bytes.get_mut(out)? = high;
                *bytes.get_mut(out.saturating_add(1))? = low;
                out = out.saturating_add(2);
            }
        }
        6 => {
            for group in groups {
                if group.is_empty() || group.len() > 2 {
                    return None;
                }
                *bytes.get_mut(out)? = u8::from_str_radix(group, 16).ok()?;
                out = out.saturating_add(1);
            }
        }
        _ => return None,
    }
    (out == 6).then_some(bytes)
}

fn bytes_literal(text: &str) -> Option<Vec<u8>> {
    if let Some(separator) = byte_separator(text) {
        let mut bytes = Vec::new();
        for group in text.split(separator) {
            if group.is_empty() || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            let (first, second) = if group.len() <= 2 {
                (group.get(..group.len())?.to_string(), String::new())
            } else if group.len() % 2 == 0 {
                (group.get(..2)?.to_string(), group.get(2..)?.to_string())
            } else {
                return None;
            };
            bytes.push(u8::from_str_radix(&first, 16).ok()?);
            let mut rest = second.as_str();
            while !rest.is_empty() {
                bytes.push(u8::from_str_radix(rest.get(..2)?, 16).ok()?);
                rest = rest.get(2..).unwrap_or_default();
            }
        }
        return (!bytes.is_empty()).then_some(bytes);
    }
    if let Some(value) = parse_integer(text) {
        if !(0..=255).contains(&value) {
            return None;
        }
        return Some(vec![u8::try_from(value).ok()?]);
    }
    if text.parse::<f64>().is_ok() {
        return None;
    }
    if !text.is_empty()
        && text.len().is_multiple_of(2)
        && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        let mut bytes = Vec::with_capacity(text.len() / 2);
        let mut rest = text;
        while !rest.is_empty() {
            bytes.push(u8::from_str_radix(rest.get(..2)?, 16).ok()?);
            rest = rest.get(2..).unwrap_or_default();
        }
        return Some(bytes);
    }
    None
}

fn byte_separator(text: &str) -> Option<char> {
    let colon = text.contains(':');
    let hyphen = text.contains('-');
    match (colon, hyphen) {
        (true, false) => Some(':'),
        (false, true) => Some('-'),
        _ => None,
    }
}

fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut bytes = [0_u8; 4];
    let mut count = 0;
    for part in text.split('.') {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let value: u16 = part.parse().ok()?;
        if value > 255 {
            return None;
        }
        *bytes.get_mut(count)? = u8::try_from(value).ok()?;
        count = count.saturating_add(1);
    }
    (count == 4).then_some(bytes)
}

fn parse_ipv6(text: &str) -> Option<[u8; 16]> {
    text.parse::<std::net::Ipv6Addr>()
        .ok()
        .map(|address| address.octets())
}

fn parse_epoch(text: &str) -> Option<(i64, u32)> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (whole, fraction) = match rest.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (rest, None),
    };
    if whole.is_empty() && fraction.is_none() {
        return None;
    }
    if !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut nanos: u128 = 0;
    if let Some(fraction) = fraction {
        if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        if fraction.len() > 10 {
            return None;
        }
        let digits: String = fraction.chars().take(9).collect();
        if !digits.is_empty() {
            nanos = digits.parse().ok()?;
            for _ in digits.len()..9 {
                nanos = nanos.checked_mul(10)?;
            }
        }
    }
    let total = whole.checked_mul(1_000_000_000)?.checked_add(nanos)?;
    let magnitude = i128::try_from(total).ok()?;
    let signed = if negative {
        magnitude.checked_neg()?
    } else {
        magnitude
    };
    let seconds = signed.div_euclid(1_000_000_000);
    let nanos = signed.rem_euclid(1_000_000_000);
    Some((i64::try_from(seconds).ok()?, u32::try_from(nanos).ok()?))
}

/// Parse an absolute time literal.
///
/// Supported: epoch seconds with an optional fraction, ISO `YYYY-MM-DD`
/// with an optional `T`/space time and optional seconds, an optional
/// `Z`/`UTC`/`±HH:MM`/`±HHMM` offset, and `Mon DD, YYYY[ HH:MM[:SS][.frac]]`.
/// Other date orderings and locale forms are not implemented.
fn parse_time_text(text: &str) -> Option<(i64, u32)> {
    let text = text.trim();
    parse_epoch(text)
        .or_else(|| parse_iso_datetime(text))
        .or_else(|| parse_month_datetime(text))
}

fn parse_iso_datetime(text: &str) -> Option<(i64, u32)> {
    let date = text.get(..10)?;
    let time = match text.get(10..) {
        Some("") => None,
        Some(rest) => {
            let rest = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('T'))?;
            Some(rest)
        }
        None => None,
    };
    let (year, month, day) = parse_date(date)?;
    let mut seconds = crate::capture::days_from_civil(year, month, day).checked_mul(86_400)?;
    let mut nanos = 0_u32;
    if let Some(time) = time {
        let (clock, offset) = split_timezone(time);
        let (seconds_of_day, fraction) = parse_time_of_day(clock, LongFraction::Ignore)?;
        seconds = seconds
            .checked_add(i64::from(seconds_of_day))?
            .checked_sub(offset)?;
        nanos = fraction;
    }
    Some((seconds, nanos))
}

fn parse_month_datetime(text: &str) -> Option<(i64, u32)> {
    let mut parts = text.split_whitespace();
    let month = month_number(parts.next()?)?;
    let day = parts.next()?.strip_suffix(',').unwrap_or_default();
    let year = parts.next()?;
    let year: i64 = year.parse().ok()?;
    let day: u32 = day.parse().ok()?;
    if year < 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > crate::capture::days_in_month(year, month)
    {
        return None;
    }
    let mut seconds = crate::capture::days_from_civil(year, month, day).checked_mul(86_400)?;
    let mut nanos = 0_u32;
    if let Some(time) = parts.next() {
        if parts.next().is_some() {
            return None;
        }
        let (clock, offset) = split_timezone(time);
        let (seconds_of_day, fraction) = parse_time_of_day(clock, LongFraction::TruncateTen)?;
        seconds = seconds
            .checked_add(i64::from(seconds_of_day))?
            .checked_sub(offset)?;
        nanos = fraction;
    }
    Some((seconds, nanos))
}

fn parse_date(text: &str) -> Option<(i64, u32, u32)> {
    let mut parts = text.split('-');
    let year = parts.next()?;
    let month = parts.next()?;
    let day = parts.next()?;
    if parts.next().is_some()
        || year.len() != 4
        || month.len() != 2
        || day.len() != 2
        || !year.bytes().all(|byte| byte.is_ascii_digit())
        || !month.bytes().all(|byte| byte.is_ascii_digit())
        || !day.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let year: i64 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    let day: u32 = day.parse().ok()?;
    if !(1..=12).contains(&month) || day == 0 || day > crate::capture::days_in_month(year, month) {
        return None;
    }
    Some((year, month, day))
}

/// Split an optional time-zone suffix and return the offset east of UTC.
fn split_timezone(text: &str) -> (&str, i64) {
    let text = text.trim();
    if let Some(rest) = text.strip_suffix(" UTC") {
        return (rest.trim_end(), 0);
    }
    if let Some(rest) = text.strip_suffix('Z') {
        return (rest, 0);
    }
    if let Some((clock, zone)) = text.rsplit_once('+')
        && let Some(offset) = parse_zone(zone)
    {
        return (clock, offset);
    }
    if let Some((clock, zone)) = text.rsplit_once('-')
        && let Some(offset) = parse_zone(zone)
    {
        return (clock, -offset);
    }
    (text, 0)
}

fn parse_zone(text: &str) -> Option<i64> {
    let (hours, minutes) = match text.split_once(':') {
        Some((hours, minutes)) => (hours, minutes),
        None => {
            if text.len() != 4 {
                return None;
            }
            (text.get(..2)?, text.get(2..)?)
        }
    };
    let hours: u32 = hours.parse().ok()?;
    let minutes: u32 = minutes.parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(i64::from(hours) * 3_600 + i64::from(minutes) * 60)
}

#[derive(Clone, Copy)]
enum LongFraction {
    /// ISO time literals ignore a fraction longer than nine digits.
    Ignore,
    /// Month-name time literals truncate a tenth digit and reject longer.
    TruncateTen,
}

fn parse_time_of_day(text: &str, long: LongFraction) -> Option<(u32, u32)> {
    let (clock, fraction) = match text.split_once('.') {
        Some((clock, fraction)) => (clock, fraction),
        None => (text, ""),
    };
    let mut fields = clock.split(':');
    let hour = fields.next()?;
    let minute = fields.next()?;
    let second = fields.next().unwrap_or("0");
    if fields.next().is_some() {
        return None;
    }
    let hour: u32 = hour.parse().ok()?;
    let minute: u32 = minute.parse().ok()?;
    let second: u32 = second.parse().ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let seconds = hour
        .checked_mul(3_600)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    Some((seconds, parse_fraction(fraction, long)?))
}

fn parse_fraction(text: &str, long: LongFraction) -> Option<u32> {
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match long {
        LongFraction::Ignore if text.len() > 9 => return Some(0),
        LongFraction::TruncateTen if text.len() > 10 => return None,
        _ => {}
    }
    if text.is_empty() {
        return Some(0);
    }
    let digits: String = text.chars().take(9).collect();
    let mut value: u32 = digits.parse().ok()?;
    for _ in digits.len()..9 {
        value = value.checked_mul(10)?;
    }
    Some(value)
}

fn month_number(name: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    MONTHS
        .iter()
        .position(|month| month.eq_ignore_ascii_case(name))
        .and_then(|index| u32::try_from(index.saturating_add(1)).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::Display;

    fn fake_field(field_type: FieldType) -> &'static FieldDef {
        Box::leak(Box::new(FieldDef {
            abbrev: "test.width",
            name: "Width",
            field_type,
            parent: "test",
            display: Display::Decimal,
            bitmask: None,
            blurb: "",
            generated: true,
        }))
    }

    #[test]
    fn literal_left_adopts_the_negated_field_width() {
        for (field_type, bits) in [
            (FieldType::Uint8, 8),
            (FieldType::Uint16, 16),
            (FieldType::Uint24, 24),
            (FieldType::Uint32, 32),
            (FieldType::Uint64, 64),
        ] {
            let field = fake_field(field_type);
            let mut left = Operand::new(
                OperandKind::TokenLiteral(TokenLiteral::Word("1".to_string())),
                0,
                1,
            );
            let right = Operand::new(
                OperandKind::Negate(Box::new(Operand::new(
                    OperandKind::Field { field, layer: None },
                    2,
                    3,
                ))),
                2,
                3,
            );
            let mut right = right;
            let mut ty = Type::Untyped;
            assert!(
                resolve_binary(ArithOp::Add, &mut left, &mut right, &mut ty, None, 0, 3).is_ok()
            );
            assert_eq!(ty, Type::Uint(bits));
        }
    }

    #[test]
    fn relative_and_absolute_times_combine_in_seconds() {
        use crate::capture::Timestamp;
        use crate::tree::Range;

        let mut frame = Node::new(&fields::FRAME_PROTOCOL, Range::new(0, 0));
        frame.add_field(
            &fields::FRAME_TIME_RELATIVE,
            Range::new(0, 0),
            Value::RelativeTime(1_500_000_000),
        );
        frame.add_field(
            &fields::FRAME_TIME_EPOCH,
            Range::new(0, 0),
            Value::AbsoluteTime(Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
        );
        let tree = Tree::new(frame);
        let matches =
            |expression: &str| Filter::parse(expression).is_ok_and(|filter| filter.matches(&tree));

        // 1.5 s relative plus 1,700,000,000 s epoch is a scalar in seconds,
        // so a whole-second comparison literal applies directly.
        assert!(matches(
            "frame.time_relative + frame.time_epoch > 1700000001"
        ));
        assert!(matches("frame.time_relative - frame.time_epoch < 0"));
        assert!(!matches(
            "frame.time_relative + frame.time_epoch > 1700000002"
        ));

        // An absolute time cannot scale another value.
        let Err(error) = Filter::parse("frame.time_relative * frame.time_epoch > 0") else {
            unreachable!("multiplication by an absolute time must be rejected")
        };
        assert!(
            error.message().contains("right-hand operand"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn nested_relative_constants_scale_from_seconds() {
        use crate::capture::Timestamp;
        use crate::tree::Range;

        let mut frame = Node::new(&fields::FRAME_PROTOCOL, Range::new(0, 0));
        frame.add_field(
            &fields::FRAME_TIME_RELATIVE,
            Range::new(0, 0),
            Value::RelativeTime(1_500_000_000),
        );
        frame.add_field(
            &fields::FRAME_TIME_EPOCH,
            Range::new(0, 0),
            Value::AbsoluteTime(Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
        );
        let mut tcp = Node::new(&fields::TCP_PROTOCOL, Range::new(34, 20));
        tcp.add_field(&fields::TCP_LEN, Range::new(38, 2), Value::Uint16(20));
        frame.add_child(tcp);
        let tree = Tree::new(frame);

        let matches =
            |expression: &str| Filter::parse(expression).is_ok_and(|filter| filter.matches(&tree));

        // The frame's relative time is 1.5 s. A nested constant expression
        // beside it counts seconds, so `1 * 1` adds one second and `10 / 4`
        // adds two and a half.
        assert!(matches("frame.time_relative + 1 * 1 > 2"));
        assert!(matches("frame.time_relative + 1 / 1 > 2"));
        assert!(matches("frame.time_relative + 10 / 4 > 3"));
        assert!(matches("frame.time_relative + 1 * 2 == 3.5"));
        assert!(matches("frame.time_relative - 1 * 1 < 1"));
        assert!(!matches("frame.time_relative - 1 * 1 > 1"));

        // Multiplication still scales the stored nanoseconds by a scalar.
        assert!(matches("frame.time_relative * 2 == 3"));
        assert!(matches("frame.time_relative * 2 > 1"));
        assert!(!matches("frame.time_relative * 2 > 3"));

        // Mixed absolute and relative arithmetic stays in seconds.
        assert!(matches(
            "frame.time_relative + frame.time_epoch > 1700000001"
        ));

        // Ordinary integer arithmetic keeps integer division and no scaling.
        assert!(matches("tcp.len + 1 * 1 == 21"));
        assert!(matches("tcp.len + 10 / 4 == 22"));
    }

    #[test]
    fn relative_constants_keep_nanosecond_precision() {
        use crate::tree::Range;

        let mut frame = Node::new(&fields::FRAME_PROTOCOL, Range::new(0, 0));
        frame.add_field(
            &fields::FRAME_TIME_RELATIVE,
            Range::new(0, 0),
            Value::RelativeTime(10_000_000_000_000_001),
        );
        let tree = Tree::new(frame);

        let matches =
            |expression: &str| Filter::parse(expression).is_ok_and(|filter| filter.matches(&tree));

        // The literal is 10000000.000000001 s. Folding it through a
        // floating-point value loses the last nanosecond, so `+ 0` would stop
        // comparing equal to the direct literal.
        assert!(matches("frame.time_relative == 10000000.000000001"));
        assert!(matches("frame.time_relative + 0 == 10000000.000000001"));

        // Constant division is exact to the nanosecond and rounds a
        // fractional nanosecond to nearest.
        assert!(matches(
            "frame.time_relative + 10 / 4 == 10000002.500000001"
        ));
        assert!(matches("frame.time_relative + 1 / 2 == 10000000.500000001"));
        assert!(matches("frame.time_relative + 1 / 3 == 10000000.333333334"));
    }

    #[test]
    fn container_and_child_fields_are_distinct_occurrences() {
        use crate::fields;
        use crate::tree::Range;

        let mut frame = Node::new(&fields::FRAME_PROTOCOL, Range::new(0, 0));
        let mut tcp = Node::new(&fields::TCP_PROTOCOL, Range::new(34, 20));
        let container = tcp.add_container(
            &fields::TCP_SEQ,
            Range::new(38, 4),
            Some("Sequence container".to_string()),
        );
        container.value = Value::Uint32(7);
        container.add_field(&fields::TCP_ACK, Range::new(42, 4), Value::Uint32(9));
        frame.add_child(tcp);
        let tree = Tree::new(frame);

        fn matches(expression: &str, tree: &Tree) -> bool {
            Filter::parse(expression).is_ok_and(|filter| filter.matches(tree))
        }

        assert!(matches("tcp.seq == 7", &tree));
        assert!(matches("tcp.ack == 9", &tree));
        assert!(!matches("tcp.seq == 9", &tree));
        assert!(matches("tcp.seq", &tree));
        assert!(matches("tcp.ack", &tree));
        assert!(matches("tcp.ack#1 == 9", &tree));
    }
}
