use nom::{
    branch::alt,
    bytes::complete::{tag, take_while},
    character::complete::{char, one_of},
    combinator::{map_res, recognize},
    multi::many1,
    sequence::{preceded, terminated},
    IResult, Parser,
};

pub(crate) fn csv<'a, F, O>(parser: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    terminated(parser, char(',')) // applies the parser followed by a comma
}

pub(crate) fn parse_utf8_string(input: &str) -> IResult<&str, String> {
    take_while(|c| c != ',')
        .map(|s: &str| s.into())
        .parse(input)
}

pub(crate) fn hexadecimal_value(input: &str) -> IResult<&str, u8> {
    map_res(
        preceded(
            alt((tag("0x"), tag("0X"))),
            recognize(many1(one_of("0123456789abcdefABCDEF"))),
        ),
        |out: &str| u8::from_str_radix(out, 16),
    )
    .parse(input)
}

#[cfg(test)]
mod test {
    use nom::character::complete::u32;

    use super::*;

    #[test]
    fn test_csv() {
        assert_eq!(Ok(("other...", 10)), csv(u32)("10,other..."));
    }
}
