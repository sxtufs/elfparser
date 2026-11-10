//! Shared Architecture-Independent Intermediate Representation (IR).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrType {
    Void,
    Int8,
    Int16,
    Int32,
    Int64,
    Int128,
    Float32,
    Float64,
}

impl IrType {
    pub fn size_bytes(&self) -> usize {
        match self {
            IrType::Void => 0,
            IrType::Int8 => 1,
            IrType::Int16 => 2,
            IrType::Int32 | IrType::Float32 => 4,
            IrType::Int64 | IrType::Float64 => 8,
            IrType::Int128 => 16,
        }
    }

    pub fn to_c_type(&self) -> &'static str {
        match self {
            IrType::Void => "void",
            IrType::Int8 => "uint8_t",
            IrType::Int16 => "uint16_t",
            IrType::Int32 => "int32_t",
            IrType::Int64 => "int64_t",
            IrType::Int128 => "uint128_t",
            IrType::Float32 => "float",
            IrType::Float64 => "double",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    DivS,
    DivU,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    ShrU,
    ShrS,
    Eq,
    Ne,
    LtS,
    LtU,
    LeS,
    LeU,
    GtS,
    GtU,
    GeS,
    GeU,
}

impl BinaryOp {
    pub fn precedence(&self) -> u8 {
        match self {
            BinaryOp::Mul | BinaryOp::DivS | BinaryOp::DivU | BinaryOp::Mod => 10,
            BinaryOp::Add | BinaryOp::Sub => 9,
            BinaryOp::Shl | BinaryOp::ShrU | BinaryOp::ShrS => 8,
            BinaryOp::LtS
            | BinaryOp::LtU
            | BinaryOp::LeS
            | BinaryOp::LeU
            | BinaryOp::GtS
            | BinaryOp::GtU
            | BinaryOp::GeS
            | BinaryOp::GeU => 7,
            BinaryOp::Eq | BinaryOp::Ne => 6,
            BinaryOp::And => 5,
            BinaryOp::Xor => 4,
            BinaryOp::Or => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrExpr {
    Const(u64),
    StringLit(String),
    Reg(String, IrType),
    StackVar {
        offset: i64,
        ty: IrType,
    },
    Unary(UnaryOp, Box<IrExpr>, IrType),
    Binary(BinaryOp, Box<IrExpr>, Box<IrExpr>, IrType),
    Load {
        ptr: Box<IrExpr>,
        ty: IrType,
    },
    Ternary {
        cond: Box<IrExpr>,
        true_val: Box<IrExpr>,
        false_val: Box<IrExpr>,
        ty: IrType,
    },
    Call {
        target: Box<IrExpr>,
        name: Option<String>,
        args: Vec<IrExpr>,
        ret_ty: IrType,
    },
}

impl IrExpr {
    pub fn reg(name: &str, ty: IrType) -> Self {
        IrExpr::Reg(name.to_lowercase(), ty)
    }

    pub fn get_type(&self) -> IrType {
        match self {
            IrExpr::Const(_) => IrType::Int64,
            IrExpr::StringLit(_) => IrType::Int64,
            IrExpr::Reg(_, ty) => *ty,
            IrExpr::StackVar { ty, .. } => *ty,
            IrExpr::Unary(_, _, ty) => *ty,
            IrExpr::Binary(_, _, _, ty) => *ty,
            IrExpr::Load { ty, .. } => *ty,
            IrExpr::Ternary { ty, .. } => *ty,
            IrExpr::Call { ret_ty, .. } => *ret_ty,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrStmt {
    Assign {
        dst: IrExpr,
        src: IrExpr,
    },
    Store {
        ptr: IrExpr,
        val: IrExpr,
        ty: IrType,
    },
    DivRem {
        quot_dst: IrExpr,
        rem_dst: IrExpr,
        dividend_high: IrExpr,
        dividend_low: IrExpr,
        divisor: IrExpr,
        is_signed: bool,
        ty: IrType,
    },
    Call {
        target: IrExpr,
        name: Option<String>,
        args: Vec<IrExpr>,
        ret_dst: Option<IrExpr>,
    },
    Branch {
        cond: Option<IrExpr>,
        target: u64,
    },
    IndirectBranch {
        target: IrExpr,
    },
    Return(Option<IrExpr>),
    Trap,
    Asm(String),
    Comment(String),
}

#[derive(Debug, Clone)]
pub struct IrBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub stmts: Vec<IrStmt>,
}

#[derive(Debug, Clone)]
pub struct ParamInfo {
    pub name: String,
    pub ty: IrType,
    pub is_ptr: bool,
    pub is_fn_ptr: bool,
}

#[derive(Debug, Clone)]
pub struct IrFunction {
    pub name: String,
    pub start_address: u64,
    pub size: u64,
    pub blocks: Vec<IrBlock>,
    pub ret_type: IrType,
    pub ret_reg: String,
    pub base_stack_offset: u64,
    pub inferred_params: Vec<ParamInfo>,
}
