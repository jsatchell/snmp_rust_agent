use log::error;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_until},
    character::complete::{alpha1, alphanumeric1, digit1, multispace0, multispace1, space0},
    combinator::{map, opt, recognize},
    multi::{many0, many0_count, separated_list1},
    sequence::{delimited, pair, preceded, terminated},
    {IResult, Parser},
};
use std::cmp::min;

#[derive(Debug, PartialEq, Clone)]
pub struct TextConvention<'a> {
    hint: &'a str,
    pub name: &'a str,
    status: &'a str,
    descr: &'a str,
    reference: &'a str,
    pub syntax: &'a str,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ParentNum<'a> {
    pub parent: &'a str,
    pub num: Vec<u32>,
}

impl ParentNum<'_> {
    fn copy(self) -> ParentNum<'static> {
        // let parent = "parent";
        let mut new_arc: Box<Vec<u32>> = Box::default();
        let name_copy: Box<String> = Box::new(self.parent.to_string());
        for num in self.num {
            new_arc.push(num);
        }
        //  let arc_ref: &'static mut Vec<u32> = Box::leak(new_arc);
        let name_ref: &'static mut String = Box::leak(name_copy);
        ParentNum {
            parent: name_ref,
            num: Box::leak(new_arc).to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ObjectIdentity<'a> {
    pub name: &'a str,
    pub status: &'a str,
    pub descr: &'a str,
    pub refer: &'a str,
    pub val: ParentNum<'a>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ObjectIdentifier<'a> {
    pub name: &'a str,
    pub val: ParentNum<'a>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ObjectType<'a> {
    pub name: &'a str,
    pub syntax: &'a str,
    pub units: &'a str,
    pub access: &'a str,
    pub status: &'a str,
    pub descr: &'a str,
    reference: &'a str,
    pub index: &'a str,
    pub augments: &'a str,
    pub defval: &'a str,
    pub val: ParentNum<'a>,
    pub col: bool,
    pub table: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct NotificationType<'a> {
    name: &'a str,
    syntax: &'a str,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ObjectGroup<'a> {
    pub name: &'a str,
    pub syntax: &'a str,
}

#[derive(Debug, PartialEq, Clone)]
pub struct NotificationGroup<'a> {
    pub name: &'a str,
    syntax: &'a str,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ModuleIdentity<'a> {
    pub name: &'a str,
    meta: &'a str,
    pub val: ParentNum<'a>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ModuleCompliance<'a> {
    name: &'a str,
    syntax: &'a str,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Entry<'a> {
    pub name: &'a str,
    pub syntax: Vec<(&'a str, &'a str)>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ImportBlock<'a> {
    pub imp_list: Vec<(Vec<&'a str>, &'a str)>,
}
#[derive(Debug, PartialEq, Clone)]
pub struct Macro {}

#[derive(Debug, PartialEq, Clone)]
pub struct Alias {}

#[derive(Debug, PartialEq, Clone)]
pub enum MibNode<'a> {
    Tc(TextConvention<'a>),
    ObIdy(ObjectIdentity<'a>),
    ObIdf(ObjectIdentifier<'a>),
    ObGrp(ObjectGroup<'a>),
    ObTy(ObjectType<'a>),
    NtGrp(NotificationGroup<'a>),
    NtTy(NotificationType<'a>),
    ModId(ModuleIdentity<'a>),
    ModCp(ModuleCompliance<'a>),
    Imp(ImportBlock<'a>),
    Ent(Entry<'a>),
    Mac(Macro),
    Al(Alias),
}

impl<'a> MibNode<'a> {
    fn mk_static_str(x: &'a str) -> &'static str {
        let x_copy: Box<String> = Box::new(x.to_string());
        let ret: &'static mut String = Box::leak(x_copy);
        ret
    }

    pub fn copy(self) -> MibNode<'static> {
        match self {
            MibNode::Tc(x) => MibNode::Tc(TextConvention {
                hint: MibNode::mk_static_str(x.hint),
                descr: MibNode::mk_static_str(x.descr),
                name: MibNode::mk_static_str(x.name),
                status: MibNode::mk_static_str(x.status),
                reference: MibNode::mk_static_str(x.reference),
                syntax: MibNode::mk_static_str(x.syntax),
            }),
            MibNode::ObIdy(x) => MibNode::ObIdy(ObjectIdentity {
                name: MibNode::mk_static_str(x.name),
                status: MibNode::mk_static_str(x.status),
                refer: MibNode::mk_static_str(x.refer),
                descr: MibNode::mk_static_str(x.descr),
                val: x.val.copy(),
            }),
            MibNode::ObIdf(x) => MibNode::ObIdf(ObjectIdentifier {
                name: MibNode::mk_static_str(x.name),
                val: x.val.copy(),
            }),
            MibNode::ObTy(x) => MibNode::ObTy(ObjectType {
                name: MibNode::mk_static_str(x.name),
                status: MibNode::mk_static_str(x.status),
                reference: MibNode::mk_static_str(x.reference),
                syntax: MibNode::mk_static_str(x.syntax),
                descr: MibNode::mk_static_str(x.descr),
                units: MibNode::mk_static_str(x.units),
                access: MibNode::mk_static_str(x.access),
                index: MibNode::mk_static_str(x.index),
                augments: MibNode::mk_static_str(x.augments),
                defval: MibNode::mk_static_str(x.defval),
                col: x.col,
                table: x.table,
                val: x.val.copy(),
            }),
            MibNode::ObGrp(x) => MibNode::ObGrp(ObjectGroup {
                name: MibNode::mk_static_str(x.name),
                syntax: MibNode::mk_static_str(x.syntax),
            }),
            MibNode::ModId(x) => MibNode::ModId(ModuleIdentity {
                name: MibNode::mk_static_str(x.name),
                meta: MibNode::mk_static_str(x.meta),
                val: x.val.copy(),
            }),
            MibNode::NtGrp(x) => MibNode::NtGrp(NotificationGroup {
                name: MibNode::mk_static_str(x.name),
                syntax: MibNode::mk_static_str(x.syntax),
            }),
            MibNode::Al(_) => MibNode::Al(Alias {}),
            MibNode::Mac(_) => MibNode::Mac(Macro {}),
            _ => {
                error!("Cant copy {self:?}");
                panic!("Not done")
            } /* MibNode::ObIdy(x) => MibNode::OIdy(),

              MibNode::ObGrp(ObjectGroup<'a>),
              MibNode::ObTy(ObjectType<'a>),
              MibNode::NtGrp(NotificationGroup<'a>),
              MibNode::NtTy(NotificationType<'a>),

              MibNode::ModCp(ModuleCompliance<'a>),
              MibNode::Imp(ImportBlock<'a>),
              MibNode::Ent(Entry<'a>),*/
        }
    }
}

pub fn uncom(text: &str) -> &'static str {
    let v: Vec<_> = text.split("\n").collect();
    let mut m = vec![];
    for item in v {
        let s = item.split("--").next().unwrap();
        m.push(s);
    }
    let x_copy: Box<String> = Box::new(m.join("\n "));
    let ret: &'static mut String = Box::leak(x_copy);
    ret
}

fn parse_cce(input: &str) -> IResult<&str, &str> {
    preceded(space0, tag("::=")).parse(input)
}

fn parse_status(input: &str) -> IResult<&str, &str> {
    preceded(
        pair(strip_ws_comment, tag("STATUS")),
        preceded(
            multispace1,
            alt((
                tag("obsolete"),
                tag("deprecated"),
                tag("current"),
                tag("mandatory"),
            )),
        ),
    )
    .parse(input)
}

fn parse_access(input: &str) -> IResult<&str, &str> {
    preceded(
        pair(strip_ws_comment, alt((tag("MAX-ACCESS"), tag("ACCESS")))),
        preceded(
            multispace1,
            alt((
                tag("not-accessible"),
                tag("read-only"),
                tag("accessible-for-notify"),
                tag("read-write"),
                tag("read-create"),
            )),
        ),
    )
    .parse(input)
}

fn parse_description(input: &str) -> IResult<&str, &str> {
    preceded(
        pair(strip_ws_comment, tag("DESCRIPTION")),
        preceded(
            multispace1,
            delimited(tag("\""), take_until("\""), tag("\"")),
        ),
    )
    .parse(input)
}

fn parse_hint(input: &str) -> IResult<&str, &str> {
    preceded(
        pair(strip_ws_comment, tag("DISPLAY-HINT")),
        preceded(
            multispace1,
            delimited(tag("\""), take_until("\""), tag("\"")),
        ),
    )
    .parse(input)
}

fn parse_reference(input: &str) -> IResult<&str, &str> {
    preceded(
        pair(strip_ws_comment, tag("REFERENCE")),
        preceded(
            multispace1,
            delimited(tag("\""), take_until("\""), tag("\"")),
        ),
    )
    .parse(input)
}

fn parse_unit(input: &str) -> IResult<&str, &str> {
    preceded(
        pair(strip_ws_comment, tag("UNITS")),
        preceded(
            multispace1,
            delimited(tag("\""), take_until("\""), tag("\"")),
        ),
    )
    .parse(input)
}

fn parse_index(input: &str) -> IResult<&str, &str> {
    preceded(
        preceded(strip_ws_comment, tag("INDEX")),
        preceded(multispace1, delimited(tag("{"), take_until("}"), tag("}"))),
    )
    .parse(input)
}

fn parse_augments(input: &str) -> IResult<&str, &str> {
    preceded(
        preceded(strip_ws_comment, tag("AUGMENTS")),
        preceded(multispace1, delimited(tag("{"), take_until("}"), tag("}"))),
    )
    .parse(input)
}

pub fn parse_macro(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        (
            preceded(strip_ws_comment, cap_name),
            multispace1,
            tag("MACRO"),
            multispace1,
            tag("::="),
            take_until("END"),
            tag("END"),
        ),
        |_| MibNode::Mac(Macro {}),
    )
    .parse(input)
}

pub fn parse_alias(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        (
            preceded(strip_ws_comment, cap_name),
            multispace1,
            tag("::="),
            alt((
                pair(
                    delimited(multispace1, tag("OCTET STRING"), multispace1),
                    delimited(tag("("), take_until("))"), tag("))")),
                ),
                pair(
                    delimited(multispace1, tag("INTEGER"), multispace1),
                    delimited(tag("("), take_until(")"), tag(")")),
                ),
                pair(multispace1, tag("INTEGER")),
                pair(multispace1, tag("OCTET STRING")),
            )),
        ),
        |_| MibNode::Al(Alias {}),
    )
    .parse(input)
}

fn parse_defval(input: &str) -> IResult<&str, &str> {
    preceded(
        pair(strip_ws_comment, tag("DEFVAL")),
        preceded(
            multispace1,
            alt((
                delimited(
                    tag("{"),
                    recognize((
                        multispace0,
                        tag("{"),
                        take_until("}"),
                        tag("}"),
                        multispace0,
                    )),
                    tag("}"),
                ),
                delimited(tag("{"), take_until("}"), tag("}")),
            )),
        ),
    )
    .parse(input)
}

pub fn parse_syntax(input: &str) -> IResult<&str, &str> {
    // Could terminate with END instead
    preceded(
        delimited(strip_ws_comment, tag("SYNTAX"), multispace1),
        recognize(pair(
            alt((
                tag("OCTET STRING"),
                tag("OBJECT IDENTIFIER"),
                tag("INTEGER"),
                recognize((
                    tag("BITS"),
                    multispace1,
                    tag("{"),
                    take_until("}"),
                    tag("}"),
                    opt(preceded(strip_ws_comment, tag("}"))),
                )),
                recognize((
                    tag("SEQUENCE"),
                    multispace1,
                    tag("OF"),
                    multispace1,
                    cap_name,
                )),
                cap_name,
            )),
            opt(alt((
                delimited(
                    preceded(strip_ws_comment, tag("{")),
                    take_until("}"),
                    tag("}"),
                ),
                delimited(
                    preceded(strip_ws_comment, tag("(")),
                    delimited(is_not("()"), tag("("), take_until("))")),
                    tag("))"),
                ),
                delimited(
                    preceded(strip_ws_comment, tag("(")),
                    take_until(")"),
                    tag(")"),
                ),
            ))),
        )),
    )
    .parse(input)
}

fn parse_def(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        pair(preceded(space0, tag("DEFINITIONS")), parse_cce),
        preceded(space0, tag("BEGIN")),
    ))
    .parse(input)
}

fn cap_name(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        preceded(space0, alt((alpha1, tag("_")))),
        many0_count(alt((alphanumeric1, tag("-")))),
    ))
    .parse(input)
}

pub fn parse_braces(input: &str) -> IResult<&str, ParentNum<'_>> {
    map(
        delimited(
            preceded(strip_ws_comment, tag("{")),
            pair(
                preceded(strip_ws_comment, cap_name),
                many0(alt((
                    preceded(multispace1, digit1),
                    delimited(delimited(multispace1, cap_name, tag("(")), digit1, tag(")")),
                ))),
            ),
            preceded(strip_ws_comment, tag("}")),
        ),
        |(parent, anum)| {
            let num: Vec<u32> = anum
                .into_iter()
                .map(|x| x.parse::<u32>().unwrap())
                .collect();
            ParentNum { parent, num }
        },
    )
    .parse(input)
}

fn parse_sbraces(input: &str) -> IResult<&str, &str> {
    recognize(delimited(
        preceded(strip_ws_comment, tag("{")),
        pair(
            preceded(strip_ws_comment, cap_name),
            many0(preceded(multispace1, digit1)),
        ),
        preceded(strip_ws_comment, tag("}")),
    ))
    .parse(input)
}

fn parse_entry_braces(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
    delimited(
        pair(strip_ws_comment, tag("{")),
        separated_list1(
            tag(","),
            preceded(
                strip_ws_comment,
                pair(
                    alphanumeric1,
                    delimited(
                        multispace1,
                        recognize(pair(
                            alt((tag("OCTET STRING"), tag("OBJECT IDENTIFIER"), alphanumeric1)),
                            opt(alt((
                                delimited(
                                    preceded(strip_ws_comment, tag("(")),
                                    delimited(is_not("()"), tag("("), take_until("))")),
                                    tag("))"),
                                ),
                                delimited(
                                    preceded(strip_ws_comment, tag("(")),
                                    take_until(")"),
                                    tag(")"),
                                ),
                            ))),
                        )),
                        strip_ws_comment,
                    ),
                ),
            ),
        ),
        pair(strip_ws_comment, tag("}")),
    )
    .parse(input)
}

pub fn parse_module_id(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            terminated(
                preceded(strip_ws_comment, cap_name),
                preceded(multispace1, tag("MODULE-IDENTITY")),
            ),
            pair(take_until("::="), preceded(tag("::="), parse_braces)),
        ),
        |(name, (meta, val))| MibNode::ModId(ModuleIdentity { name, meta, val }),
    )
    .parse(input)
}

fn parse_imports(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            preceded(strip_ws_comment, tag("IMPORTS")),
            terminated(
                many0(pair(
                    separated_list1(
                        tag(","),
                        delimited(strip_ws_comment, cap_name, strip_ws_comment),
                    ),
                    preceded(
                        tag("FROM"),
                        delimited(strip_ws_comment, cap_name, strip_ws_comment),
                    ),
                )),
                tag(";"),
            ),
        ),
        |(_, i)| MibNode::Imp(ImportBlock { imp_list: i }),
    )
    .parse(input)
}

pub fn parse_obj_type(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            terminated(
                delimited(strip_ws_comment, alphanumeric1, multispace1),
                tag("OBJECT-TYPE"),
            ),
            (
                parse_syntax,
                opt(parse_unit),
                parse_access,
                parse_status,
                parse_description,
                opt(parse_reference),
                opt(parse_index),
                opt(parse_augments),
                opt(parse_defval),
                preceded(strip_ws_comment, tag("::=")),
                parse_braces,
            ),
        ),
        |(
            name,
            (
                syntax,
                unit_opt,
                access,
                status,
                descr,
                ref_opt,
                idx_opt,
                aug_opt,
                defv_opt,
                _tag,
                val,
            ),
        )| {
            let units = unit_opt.unwrap_or("");
            let augments = aug_opt.unwrap_or("");
            let index = idx_opt.unwrap_or("");
            let defval = defv_opt.unwrap_or("");
            let reference = ref_opt.unwrap_or("");
            let table = syntax.contains("SEQUENCE") && syntax.contains("OF");
            MibNode::ObTy(ObjectType {
                name,
                syntax,
                units,
                access,
                status,
                descr,
                reference,
                index,
                augments,
                defval,
                val,
                col: false,
                table,
            })
        },
    )
    .parse(input)
}

pub fn parse_notification_type(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            terminated(
                delimited(strip_ws_comment, alphanumeric1, multispace1),
                tag("NOTIFICATION-TYPE"),
            ),
            recognize(pair(take_until("::="), pair(tag("::="), parse_sbraces))),
        ),
        |(name, syntax)| MibNode::NtTy(NotificationType { name, syntax }),
    )
    .parse(input)
}

pub fn parse_tc(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            delimited(
                strip_ws_comment,
                alphanumeric1,
                pair(strip_ws_comment, tag("::=")),
            ),
            pair(
                preceded(
                    pair(strip_ws_comment, tag("TEXTUAL-CONVENTION")),
                    (opt(parse_hint), parse_status, parse_description),
                ),
                pair(opt(parse_reference), parse_syntax),
            ),
        ),
        |(name, ((hint_opt, status, descr), (refer_opt, syntax)))| {
            let reference = refer_opt.unwrap_or("");
            let hint = hint_opt.unwrap_or("");
            MibNode::Tc(TextConvention {
                hint,
                name,
                status,
                descr,
                reference,
                syntax: uncom(syntax),
            })
        },
    )
    .parse(input)
}

fn parse_mod_comp(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            terminated(
                delimited(strip_ws_comment, alphanumeric1, multispace1),
                tag("MODULE-COMPLIANCE"),
            ),
            recognize(pair(take_until("::="), pair(tag("::="), parse_sbraces))),
        ),
        |(name, syntax)| MibNode::ModCp(ModuleCompliance { name, syntax }),
    )
    .parse(input)
}

pub fn parse_object_identity(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        (
            delimited(strip_ws_comment, alphanumeric1, multispace1),
            tag("OBJECT-IDENTITY"),
            parse_status,
            parse_description,
            opt(parse_reference),
            preceded(strip_ws_comment, tag("::=")),
            parse_braces,
        ),
        |(name, _, status, descr, ref_opt, _, val)| {
            let refer = ref_opt.unwrap_or("");
            MibNode::ObIdy(ObjectIdentity {
                name,
                status,
                descr,
                refer,
                val,
            })
        },
    )
    .parse(input)
}

pub fn parse_object_identifier(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            terminated(
                delimited(strip_ws_comment, cap_name, multispace1),
                tag("OBJECT IDENTIFIER"),
            ),
            preceded(pair(strip_ws_comment, tag("::=")), parse_braces),
        ),
        |(name, val)| MibNode::ObIdf(ObjectIdentifier { name, val }),
    )
    .parse(input)
}

fn parse_object_group(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            terminated(
                delimited(strip_ws_comment, alphanumeric1, multispace1),
                tag("OBJECT-GROUP"),
            ),
            recognize(pair(take_until("::="), pair(tag("::="), parse_sbraces))),
        ),
        |(name, syntax)| MibNode::ObGrp(ObjectGroup { name, syntax }),
    )
    .parse(input)
}

fn parse_notification_group(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            terminated(
                delimited(strip_ws_comment, alphanumeric1, multispace1),
                tag("NOTIFICATION-GROUP"),
            ),
            recognize(pair(take_until("::="), pair(tag("::="), parse_sbraces))),
        ),
        |(name, syntax)| MibNode::NtGrp(NotificationGroup { name, syntax }),
    )
    .parse(input)
}

pub fn parse_entry(input: &str) -> IResult<&str, MibNode<'_>> {
    map(
        pair(
            terminated(
                delimited(strip_ws_comment, alphanumeric1, multispace0),
                pair(tag("::="), multispace1),
            ),
            preceded(tag("SEQUENCE"), parse_entry_braces),
        ),
        |(name, syntax)| MibNode::Ent(Entry { name, syntax }),
    )
    .parse(input)
}

pub fn parse_defs(input: &str) -> IResult<&str, Vec<MibNode<'_>>> {
    many0(alt([
        parse_obj_type,
        parse_object_identity,
        parse_object_identifier,
        parse_object_group,
        parse_notification_type,
        parse_notification_group,
        parse_entry,
        parse_mod_comp,
        parse_tc,
        parse_macro,
        parse_alias,
        parse_module_id,
    ]))
    .parse(input)
}

pub fn comment(input: &str) -> IResult<&str, &str> {
    preceded(multispace0, alt((block_comment, line_comment))).parse(input)
}

pub fn line_comment(input: &str) -> IResult<&str, &str> {
    delimited(tag("--"), take_until("\n"), opt(tag("--"))).parse(input)
}

pub fn block_comment(input: &str) -> IResult<&str, &str> {
    delimited(tag("/*"), take_until("*/"), tag("*/")).parse(input)
}

pub fn strip_ws_comment(input: &str) -> IResult<&str, Vec<&str>> {
    many0(alt((multispace1, comment))).parse(input)
}

pub fn parse_end(input: &str) -> IResult<&str, &str> {
    preceded(strip_ws_comment, tag("END")).parse(input)
}

pub fn parse_mib<'a>(input: &'a str, nodes: &mut Vec<MibNode<'a>>) -> (bool, u32) {
    let cap_res = cap_name(input);
    if cap_res.is_err() {
        return (false, 1);
    }
    let (leftover_input, _mod_name) = cap_res.unwrap();

    let (abc, _def) = parse_def(leftover_input).unwrap();

    let imp_res = parse_imports(abc);
    let body;
    let imps;
    if imp_res.is_err() {
        //let deb = &abc[0..128];
        return (false, 2);
        // body = abc;
    } else {
        (body, imps) = imp_res.unwrap();
        nodes.push(imps);
    }

    let (end, mut defs) = parse_defs(body).unwrap();
    nodes.append(&mut defs);
    let _obj_id: Vec<&MibNode> = defs
        .iter()
        .filter(|&x| matches!(*x, MibNode::ObIdf(_)))
        .collect();
    let _ents: Vec<&MibNode> = defs
        .iter()
        .filter(|&x| matches!(*x, MibNode::Ent(_)))
        .collect();

    let end_ok = parse_end(end);
    if end_ok.is_err() {
        let l = min(32, end.len());
        let deb = &end[0..l];
        error!("{deb}\n------------------------");
        (false, 4)
    } else {
        (true, 0)
    }
}
