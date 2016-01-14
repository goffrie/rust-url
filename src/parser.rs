// Copyright 2013-2014 Simon Sapin.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ascii::AsciiExt;
use std::cmp::max;
use std::error::Error;
use std::fmt::{self, Formatter};

use super::{Url, HostInternal, EncodingOverride};
use host::Host;
use percent_encoding::{
    utf8_percent_encode_to, percent_encode_to,
    SIMPLE_ENCODE_SET, DEFAULT_ENCODE_SET, USERINFO_ENCODE_SET, QUERY_ENCODE_SET
};

pub type ParseResult<T> = Result<T, ParseError>;

macro_rules! simple_enum_error {
    ($($name: ident => $description: expr,)+) => {
        /// Errors that can occur during parsing.
        #[derive(PartialEq, Eq, Clone, Copy, Debug)]
        pub enum ParseError {
            $(
                $name,
            )+
        }

        impl Error for ParseError {
            fn description(&self) -> &str {
                match *self {
                    $(
                        ParseError::$name => $description,
                    )+
                }
            }
        }
    }
}

simple_enum_error! {
    EmptyHost => "empty host",
    InvalidScheme => "invalid scheme",
    InvalidPort => "invalid port number",
    InvalidIpv4Address => "invalid IPv4 address",
    InvalidIpv6Address => "invalid IPv6 address",
    InvalidDomainCharacter => "invalid domain character",
    InvalidCharacter => "invalid character",
    InvalidBackslash => "invalid backslash",
    InvalidPercentEncoded => "invalid percent-encoded sequence",
    InvalidAtSymbolInUser => "invalid @-symbol in user",
    ExpectedTwoSlashes => "expected two slashes (//)",
    ExpectedInitialSlash => "expected the input to start with a slash",
    NonUrlCodePoint => "non URL code point",
    RelativeUrlWithScheme => "relative URL with scheme",
    RelativeUrlWithoutBase => "relative URL without a base",
    RelativeUrlWithNonRelativeBase => "relative URL with a non-relative base",
    NonAsciiDomainsNotSupportedYet => "non-ASCII domains are not supported yet",
    CannotSetJavascriptFragment => "cannot set fragment on javascript: URL",
    CannotSetPortWithFileLikeScheme => "cannot set port with file-like scheme",
    CannotSetUsernameWithNonRelativeScheme => "cannot set username with non-relative scheme",
    CannotSetPasswordWithNonRelativeScheme => "cannot set password with non-relative scheme",
    CannotSetHostPortWithNonRelativeScheme => "cannot set host and port with non-relative scheme",
    CannotSetHostWithNonRelativeScheme => "cannot set host with non-relative scheme",
    CannotSetPortWithNonRelativeScheme => "cannot set port with non-relative scheme",
    CannotSetPathWithNonRelativeScheme => "cannot set path with non-relative scheme",
    Overflow => "URLs more than 4 GB are not supported",
}

impl fmt::Display for ParseError {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        self.description().fmt(fmt)
    }
}

/// This is called on non-fatal parse errors.
///
/// The handler can choose to continue or abort parsing by returning Ok() or Err(), respectively.
/// See the `UrlParser::error_handler` method.
///
/// FIXME: make this a by-ref closure when that’s supported.
pub type ErrorHandler = fn(reason: ParseError) -> ParseResult<()>;

#[derive(PartialEq, Eq)]
pub enum Context {
    UrlParser,
    Setter,
}

#[derive(Copy, Clone)]
enum SchemeType {
    File,
    SpecialNotFile,
    NotSpecial,
}

impl SchemeType {
    fn is_special(&self) -> bool {
        !matches!(*self, SchemeType::NotSpecial)
    }

    fn is_file(&self) -> bool {
        matches!(*self, SchemeType::File)
    }

    fn from(s: &str) -> Self {
        match s {
            "http" | "https" | "ws" | "wss" | "ftp" | "gopher" => SchemeType::SpecialNotFile,
            "file" => SchemeType::File,
            _ => SchemeType::NotSpecial,
        }
    }
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        "gopher" => Some(70),
        _ => None,
    }
}

pub struct Parser<'a> {
    pub serialization: String,
    pub base_url: Option<&'a Url>,
    pub query_encoding_override: EncodingOverride,
    pub log_syntax_violation: Option<&'a Fn(&'static str)>,
}

impl<'a> Parser<'a> {
    fn syntax_violation(&self, reason: &'static str) {
        if let Some(log) = self.log_syntax_violation {
            log(reason)
        }
    }

    fn syntax_violation_if<F: Fn() -> bool>(&self, reason: &'static str, test: F) {
        // Skip test if not logging.
        if let Some(log) = self.log_syntax_violation {
            if test() {
                log(reason)
            }
        }
    }

    /// https://url.spec.whatwg.org/#concept-basic-url-parser
    pub fn parse_url(mut self, original_input: &str) -> ParseResult<Url> {
        let input = original_input.trim_matches(c0_control_or_space);
        if input.len() < original_input.len() {
            self.syntax_violation("leading or trailing control or space character")
        }
        let (scheme_end, remaining) = if let Ok(remaining) = self.parse_scheme(input, Context::UrlParser) {
            (try!(to_u32(self.serialization.len())), remaining)
        } else {
            // No-scheme state
            return if let Some(base_url) = self.base_url {
                if input.starts_with("#") {
                    self.fragment_only(base_url, input)
                } else if base_url.non_relative {
                    Err(ParseError::RelativeUrlWithNonRelativeBase)
                } else {
                    let base_scheme_type = SchemeType::from(base_url.scheme());
                    if base_scheme_type.is_file() {
                        // file state
                        unimplemented!()
                    } else {
                        // relative state
    //                        let scheme_type = self.get_scheme_type(&scheme);
    //                        parse_relative_url(input, scheme.clone(), scheme_type, base, query, parser)
    //                        ....
                        unimplemented!();
                    }
                }
            } else {
                Err(ParseError::RelativeUrlWithoutBase)
            }
        };
        let scheme_type = SchemeType::from(&self.serialization);
        self.serialization.push(':');
        match scheme_type {
            SchemeType::File => {
                self.syntax_violation_if("expected // after file:", || {
                    !remaining.starts_with("//")
                });
                // File state
                unimplemented!()
    //            // Relative state?
    //            match self.base_url {
    //                Some(&Url { scheme: ref base_scheme, scheme_data: SchemeData::Relative(ref base),
    //                            ref query, .. })
    //                if scheme == *base_scheme => {
    //                    parse_relative_url(remaining, scheme, scheme_type, base, query, parser)
    //                },
    //                // FIXME: Should not have to use a made-up base URL.
    //                _ => parse_relative_url(remaining, scheme, scheme_type, &RelativeSchemeData {
    //                    username: String::new(), password: None, host: Host::Domain(String::new()),
    //                    port: None, default_port: None, path: Vec::new()
    //                }, &None, parser)
    //            }
            },
            SchemeType::SpecialNotFile => {
                match self.base_url {
                    Some(base_url) if base_url.scheme() == &self.serialization[..scheme_end as usize] => {
                        // special relative or authority state
                        unimplemented!();
//                        if scheme == *base_scheme && !remaining.starts_with("//") => {
//                            try!(self.syntax_violation(ParseError::RelativeUrlWithScheme));
//                            parse_relative_url(remaining, scheme, scheme_type, base, query, parser)
                    }
                    _ => {
                        // special authority slashes state
                        unimplemented!();
//                        parse_absolute_url(scheme, scheme_type, remaining, parser)
                    }
                }
            },
            SchemeType::NotSpecial => {
                if remaining.starts_with("//") {
                    self.serialization.push('/');
                    self.serialization.push('/');
                    let remaining = &remaining[2..];
                    // authority state
                    let (username_end, remaining) =
                        try!(self.parse_userinfo(remaining, scheme_type));
                    let host_start = try!(to_u32(self.serialization.len()));
                    let (host_end, host, port, remaining) =
                        try!(self.parse_host_and_port(remaining, scheme_end));
                    let path_start = try!(to_u32(self.serialization.len()));
                    unimplemented!();
                } else {
                    // Anarchist URL (no authority)
                    let path_start = try!(to_u32(self.serialization.len()));
                    let remaining = if remaining.starts_with("/") {
                        self.serialization.push('/');
                        self.parse_path(scheme_type, &mut false, &remaining[1..], Context::UrlParser)
                    } else {
                        self.parse_non_relative_path(remaining)
                    };
                    let (query_start, fragment_start) =
                        try!(self.parse_query_and_fragment(scheme_end, remaining));
                    Ok(Url {
                        serialization: self.serialization,
                        non_relative: true,
                        scheme_end: scheme_end,
                        username_end: path_start,
                        host_start: path_start,
                        host_end: path_start,
                        host: HostInternal::None,
                        port: None,
                        path_start: path_start,
                        query_start: query_start,
                        fragment_start: fragment_start
                    })
                }
            }
        }
    }

    pub fn parse_scheme<'i>(&mut self, input: &'i str, context: Context) -> ParseResult<&'i str> {
        if input.is_empty() || !input.starts_with(ascii_alpha) {
            return Err(ParseError::InvalidScheme)
        }
        debug_assert!(self.serialization.is_empty());
        for (i, c) in input.char_indices() {
            match c {
                'a'...'z' | 'A'...'Z' | '0'...'9' | '+' | '-' | '.' => {
                    self.serialization.push(c.to_ascii_lowercase())
                }
                ':' => return Ok(&input[i + 1..]),
                _ => {
                    self.serialization.clear();
                    return Err(ParseError::InvalidScheme)
                }
            }
        }
        // EOF before ':'
        match context {
            Context::Setter => Ok(""),
            Context::UrlParser => {
                self.serialization.clear();
                Err(ParseError::InvalidScheme)
            }
        }
    }

    //fn parse_absolute_url<'i>(scheme: String, scheme_type: SchemeType,
    //                          input: &'i str, parser: &mut Parser) -> ParseResult<Url> {
    //    // Authority first slash state
    //    let remaining = try!(skip_slashes(input, parser));
    //    // Authority state
    //    let (username, password, remaining) = try!(p_arse_userinfo(remaining, parser));
    //    // Host state
    //    let (host, port, default_port, remaining) = try!(parse_host(remaining, scheme_type, parser));
    //    let (path, remaining) = try!(parse_path_start(
    //        remaining, Context::UrlParser, scheme_type, parser));
    //    let scheme_data = SchemeData::Relative(RelativeSchemeData {
    //        username: username, password: password,
    //        host: host, port: port, default_port: default_port,
    //        path: path });
    //    let (query, fragment) = try!(parse_query_and_fragment(remaining, parser));
    //    Ok(Url { scheme: scheme, scheme_data: scheme_data, query: query, fragment: fragment })
    //}

    //fn parse_relative_url<'i>(input: &'i str, scheme: String, scheme_type: SchemeType,
    //                          base: &RelativeSchemeData, base_query: &Option<String>,
    //                          parser: &mut Parser)
    //                          -> ParseResult<Url> {
    //    let mut chars = input.chars();
    //    match chars.next() {
    //        Some('/') | Some('\\') => {
    //            let ch = chars.next();
    //            // Relative slash state
    //            if matches!(ch, Some('/') | Some('\\')) {
    //                if ch == Some('\\') {
    //                    try!(self.syntax_violation(ParseError::InvalidBackslash))
    //                }
    //                if scheme_type == SchemeType::FileLike {
    //                    // File host state
    //                    let remaining = &input[2..];
    //                    let (host, remaining) = if remaining.len() >= 2
    //                       && starts_with_ascii_alpha(remaining)
    //                       && matches!(remaining.as_bytes()[1], b':' | b'|')
    //                       && (remaining.len() == 2
    //                           || matches!(remaining.as_bytes()[2],
    //                                         b'/' | b'\\' | b'?' | b'#'))
    //                    {
    //                        // Windows drive letter quirk
    //                        (Host::Domain(String::new()), remaining)
    //                    } else {
    //                        try!(parse_file_host(remaining, parser))
    //                    };
    //                    let (path, remaining) = try!(parse_path_start(
    //                        remaining, Context::UrlParser, scheme_type, parser));
    //                    let scheme_data = SchemeData::Relative(RelativeSchemeData {
    //                        username: String::new(), password: None,
    //                        host: host, port: None, default_port: None, path: path
    //                    });
    //                    let (query, fragment) = try!(parse_query_and_fragment(remaining, parser));
    //                    Ok(Url { scheme: scheme, scheme_data: scheme_data,
    //                             query: query, fragment: fragment })
    //                } else {
    //                    parse_absolute_url(scheme, scheme_type, input, parser)
    //                }
    //            } else {
    //                // Relative path state
    //                let (path, remaining) = try!(parse_path(
    //                    &[], &input[1..], Context::UrlParser, scheme_type, parser));
    //                let scheme_data = SchemeData::Relative(if scheme_type == SchemeType::FileLike {
    //                    RelativeSchemeData {
    //                        username: String::new(), password: None, host:
    //                        Host::Domain(String::new()), port: None, default_port: None, path: path
    //                    }
    //                } else {
    //                    RelativeSchemeData {
    //                        username: base.username.clone(),
    //                        password: base.password.clone(),
    //                        host: base.host.clone(),
    //                        port: base.port.clone(),
    //                        default_port: base.default_port.clone(),
    //                        path: path
    //                    }
    //                });
    //                let (query, fragment) = try!(
    //                    parse_query_and_fragment(remaining, parser));
    //                Ok(Url { scheme: scheme, scheme_data: scheme_data,
    //                         query: query, fragment: fragment })
    //            }
    //        },
    //        Some('?') => {
    //            let (query, fragment) = try!(parse_query_and_fragment(input, parser));
    //            Ok(Url { scheme: scheme, scheme_data: SchemeData::Relative(base.clone()),
    //                     query: query, fragment: fragment })
    //        },
    //        Some('#') => {
    //            let fragment = Some(try!(parse_fragment(&input[1..], parser)));
    //            Ok(Url { scheme: scheme, scheme_data: SchemeData::Relative(base.clone()),
    //                     query: base_query.clone(), fragment: fragment })
    //        }
    //        None => {
    //            Ok(Url { scheme: scheme, scheme_data: SchemeData::Relative(base.clone()),
    //                     query: base_query.clone(), fragment: None })
    //        }
    //        _ => {
    //            let (scheme_data, remaining) = if scheme_type == SchemeType::FileLike
    //               && input.len() >= 2
    //               && starts_with_ascii_alpha(input)
    //               && matches!(input.as_bytes()[1], b':' | b'|')
    //               && (input.len() == 2
    //                   || matches!(input.as_bytes()[2], b'/' | b'\\' | b'?' | b'#'))
    //            {
    //                // Windows drive letter quirk
    //                let (path, remaining) = try!(parse_path(
    //                    &[], input, Context::UrlParser, scheme_type, parser));
    //                 (SchemeData::Relative(RelativeSchemeData {
    //                    username: String::new(), password: None,
    //                    host: Host::Domain(String::new()),
    //                    port: None,
    //                    default_port: None,
    //                    path: path
    //                }), remaining)
    //            } else {
    //                let base_path = &base.path[..max(base.path.len(), 1) - 1];
    //                // Relative path state
    //                let (path, remaining) = try!(parse_path(
    //                    base_path, input, Context::UrlParser, scheme_type, parser));
    //                (SchemeData::Relative(RelativeSchemeData {
    //                    username: base.username.clone(),
    //                    password: base.password.clone(),
    //                    host: base.host.clone(),
    //                    port: base.port.clone(),
    //                    default_port: base.default_port.clone(),
    //                    path: path
    //                }), remaining)
    //            };
    //            let (query, fragment) = try!(parse_query_and_fragment(remaining, parser));
    //            Ok(Url { scheme: scheme, scheme_data: scheme_data,
    //                     query: query, fragment: fragment })
    //        }
    //    }
    //}

    //fn skip_slashes<'i>(input: &'i str, parser: &mut Parser) -> ParseResult<&'i str> {
    //    let first_non_slash = input.find(|c| !matches!(c, '/' | '\\')).unwrap_or(input.len());
    //    if &input[..first_non_slash] != "//" {
    //        try!(self.syntax_violation(ParseError::ExpectedTwoSlashes));
    //    }
    //    Ok(&input[first_non_slash..])
    //}

    /// Return (username_end, remaining)
    fn parse_userinfo<'i>(&mut self, input: &'i str, scheme_type: SchemeType)
                          -> ParseResult<(u32, &'i str)> {
        let mut last_at = None;
        for (i, c) in input.char_indices() {
            match c {
                '@' => {
                    if last_at.is_some() {
                        self.syntax_violation("unencoded @ sign in username or password")
                    } else {
                        self.syntax_violation(
                            "embedding authentification information (username or password) \
                            in an URL is not recommended")
                    }
                    last_at = Some(i)
                },
                '/' | '?' | '#' => break,
                '\\' if scheme_type.is_special() => break,
                _ => (),
            }
        }
        let (input, remaining) = match last_at {
            Some(at) => (&input[..at], &input[at + 1..]),
            None => return Ok((try!(to_u32(self.serialization.len())), input)),
        };

        let mut username_end = None;
        for (i, c, next_i) in input.char_ranges() {
            match c {
                ':' if username_end.is_none() => {
                    // Start parsing password
                    username_end = Some(try!(to_u32(i)));
                    self.serialization.push(':');
                },
                '\t' | '\n' | '\r' => {},
                _ => {
                    self.check_url_code_point(input, i, c);
                    let utf8_c = &input[i..next_i];
                    utf8_percent_encode_to(utf8_c, USERINFO_ENCODE_SET, &mut self.serialization);
                }
            }
        }
        self.serialization.push('@');
        let username_end = match username_end {
            Some(i) => i,
            None => try!(to_u32(self.serialization.len())),
        };
        Ok((username_end, remaining))
    }

    pub fn parse_host_and_port<'i>(&mut self, input: &'i str, scheme_end: u32)
                                   -> ParseResult<(u32, HostInternal, Option<u16>, &'i str)> {
        let (host, remaining) = try!(self.parse_host(input));
        let host_end = try!(to_u32(self.serialization.len()));
        let (port, remaining) = if remaining.starts_with(":") {
            try!(self.parse_port(&remaining[1..], scheme_end))
        } else {
            (None, remaining)
        };
        Ok((host_end, host, port, remaining))
    }

    pub fn parse_host<'i>(&mut self, input: &'i str) -> ParseResult<(HostInternal, &'i str)> {
        let mut inside_square_brackets = false;
        let mut host_input = String::new();
        let mut end = input.len();
        for (i, c) in input.char_indices() {
            match c {
                ':' if !inside_square_brackets => {
                    end = i;
                    break
                },
                '/' | '\\' | '?' | '#' => {
                    end = i;
                    break
                },
                '\t' | '\n' | '\r' => self.syntax_violation("invalid character"),
                c => {
                    match c {
                        '[' => inside_square_brackets = true,
                        ']' => inside_square_brackets = false,
                        _ => (),
                    }
                    host_input.push(c)
                }
            }
        }
        unimplemented!();
        let host = try!(Host::parse(&host_input));
        Ok((host, &input[end..]))
    }

    pub fn parse_port<'i>(&mut self, input: &'i str, scheme_end: u32)
                          -> ParseResult<(Option<u16>, &'i str)> {
        let default_port = default_port(&self.serialization[..scheme_end as usize]);
        unimplemented!();
    //    let mut port = 0;
    //    let mut has_any_digit = false;
    //    let mut end = input.len();
    //    for (i, c) in input.char_indices() {
    //        match c {
    //            '0'...'9' => {
    //                port = port * 10 + (c as u32 - '0' as u32);
    //                if port > ::std::u16::MAX as u32 {
    //                    return Err(ParseError::InvalidPort)
    //                }
    //                has_any_digit = true;
    //            },
    //            '/' | '\\' | '?' | '#' => {
    //                end = i;
    //                break
    //            },
    //            '\t' | '\n' | '\r' => try!(self.syntax_violation(ParseError::InvalidCharacter)),
    //            _ => return Err(ParseError::InvalidPort)
    //        }
    //    }
    //    let default_port = scheme_type.default_port();
    //    let mut port = Some(port as u16);
    //    if !has_any_digit || port == default_port {
    //        port = None;
    //    }
    //    return Ok((port, default_port, &input[end..]))
    }

    //fn parse_file_host<'i>(input: &'i str, parser: &mut Parser) -> ParseResult<(Host, &'i str)> {
    //    let mut host_input = String::new();
    //    let mut end = input.len();
    //    for (i, c) in input.char_indices() {
    //        match c {
    //            '/' | '\\' | '?' | '#' => {
    //                end = i;
    //                break
    //            },
    //            '\t' | '\n' | '\r' => try!(self.syntax_violation(ParseError::InvalidCharacter)),
    //            _ => host_input.push(c)
    //        }
    //    }
    //    let host = if host_input.is_empty() {
    //        Host::Domain(String::new())
    //    } else {
    //        try!(Host::parse(&host_input))
    //    };
    //    Ok((host, &input[end..]))
    //}

    //pub fn parse_standalone_path(input: &str, parser: &mut Parser)
    //                             -> ParseResult<(Vec<String>, Option<String>, Option<String>)> {
    //    if !input.starts_with("/") {
    //        if input.starts_with("\\") {
    //            try!(self.syntax_violation(ParseError::InvalidBackslash));
    //        } else {
    //            return Err(ParseError::ExpectedInitialSlash)
    //        }
    //    }
    //    let (path, remaining) = try!(parse_path(
    //        &[], &input[1..], Context::UrlParser, SchemeType::Relative(0), parser));
    //    let (query, fragment) = try!(parse_query_and_fragment(remaining, parser));
    //    Ok((path, query, fragment))
    //}

    //pub fn parse_path_start<'i>(input: &'i str, context: Context, scheme_type: SchemeType,
    //                            parser: &mut Parser)
    //                            -> ParseResult<(Vec<String>, &'i str)> {
    //    let mut i = 0;
    //    // Relative path start state
    //    match input.chars().next() {
    //        Some('/') => i = 1,
    //        Some('\\') => {
    //            try!(self.syntax_violation(ParseError::InvalidBackslash));
    //            i = 1;
    //        },
    //        _ => ()
    //    }
    //    parse_path(&[], &input[i..], context, scheme_type, parser)
    //}

    fn parse_path<'i>(&mut self, scheme_type: SchemeType, has_host: &mut bool,
                      input: &'i str, context: Context)
                      -> &'i str {
        // Relative path state
        let path_start = self.serialization.len();  // After initial '/', unlike Url::path_start
        let mut iter = input.char_ranges();
        let mut end;
        loop {
            let component_start = self.serialization.len();
            let mut ends_with_slash = false;
            end = input.len();
            while let Some((i, c, next_i)) = iter.next() {
                match c {
                    '/' => {
                        ends_with_slash = true;
                        end = i;
                        break
                    },
                    '\\' if scheme_type.is_special() => {
                        self.syntax_violation("backslash");
                        ends_with_slash = true;
                        end = i;
                        break
                    },
                    '?' | '#' if context == Context::UrlParser => {
                        end = i;
                        break
                    },
                    '\t' | '\n' | '\r' => self.syntax_violation("invalid characters"),
                    _ => {
                        self.check_url_code_point(input, i, c);
                        utf8_percent_encode_to(
                            &input[i..next_i], DEFAULT_ENCODE_SET, &mut self.serialization);
                    }
                }
            }
            match &self.serialization[component_start..] {
                ".." | ".%2e" | ".%2E" | "%2e." | "%2E." |
                "%2e%2e" | "%2E%2e" | "%2e%2E" | "%2E%2E" => {
                    self.pop_path(scheme_type, path_start, component_start)
                },
                "." | "%2e" | "%2E" => {
                    self.serialization.truncate(component_start);
                },
                _ => {
                    if is_windows_drive_letter(scheme_type, &self.serialization[path_start..]) {
                        unsafe {
                            *self.serialization.as_mut_vec().last_mut().unwrap() = b':'
                        }
                        if *has_host {
                            self.syntax_violation("file: with host and Windows drive letter");
                            *has_host = false;
                        }
                    }
                    if ends_with_slash {
                        self.serialization.push('/')
                    }
                }
            }
            if !ends_with_slash {
                break
            }
        }
        &input[end..]
    }

    /// https://url.spec.whatwg.org/#pop-a-urls-path
    fn pop_path(&mut self, scheme_type: SchemeType, path_start: usize, component_start: usize) {
        // Truncate at least ".."
        let mut truncate_to = component_start;

        if component_start != path_start {
            debug_assert!(self.serialization[path_start..component_start].ends_with("/"));
            let previous_component_end = component_start - 1;
            let before_this_component = &self.serialization[path_start..previous_component_end];
            let previous_component_start = match before_this_component.rfind('/') {
                Some(slash_position) => path_start + slash_position + "/".len(),
                None => path_start,
            };
            // Don’t pop a Windows drive letter
            if !is_windows_drive_letter(
                scheme_type,
                &self.serialization[previous_component_start..previous_component_end]
            ) {
                truncate_to = previous_component_start
            }
        };

        self.serialization.truncate(truncate_to);
    }

    fn parse_non_relative_path<'i>(&mut self, input: &'i str) -> &'i str {
        let mut end = input.len();
        for (i, c, next_i) in input.char_ranges() {
            match c {
                '?' | '#' => return &input[i..],
                '\t' | '\n' | '\r' => self.syntax_violation("invalid character"),
                _ => {
                    self.check_url_code_point(input, i, c);
                    utf8_percent_encode_to(
                        &input[i..next_i], SIMPLE_ENCODE_SET, &mut self.serialization);
                }
            }
        }
        ""
    }

    /// Return (query_start, fragment_start)
    fn parse_query_and_fragment(&mut self, scheme_end: u32, mut input: &str)
                                -> ParseResult<(Option<u32>, Option<u32>)> {
        let mut query_start = None;
        match input.chars().next() {
            Some('#') => {}
            Some('?') => {
                query_start = Some(try!(to_u32(self.serialization.len())));
                self.serialization.push('?');
                let remaining = self.parse_query(scheme_end, &input[1..], Context::UrlParser);
                if let Some(remaining) = remaining {
                    input = remaining
                } else {
                    return Ok((query_start, None))
                }
            }
            None => return Ok((None, None)),
            _ => panic!("Programming error. parse_query_and_fragment() should not \
                        have been called with input \"{}\"", input)
        };

        let fragment_start = try!(to_u32(self.serialization.len()));
        self.serialization.push('#');
        self.parse_fragment(&input[1..]);
        Ok((query_start, Some(fragment_start)))
    }

    pub fn parse_query<'i>(&mut self, scheme_end: u32, input: &'i str, context: Context)
                           -> Option<&'i str> {
        let mut query = String::new();  // FIXME: use a streaming decoder instead
        let mut remaining = None;
        for (i, c) in input.char_indices() {
            match c {
                '#' if context == Context::UrlParser => {
                    remaining = Some(&input[i + 1..]);
                    break
                },
                '\t' | '\n' | '\r' => self.syntax_violation("invalid characters"),
                _ => {
                    self.check_url_code_point(input, i, c);
                    query.push(c);
                }
            }
        }

        let encoding = match &self.serialization[..scheme_end as usize] {
            "http" | "https" | "file" | "ftp" | "gopher" => self.query_encoding_override,
            _ => EncodingOverride::utf8(),
        };
        let query_bytes = encoding.encode(&query);
        percent_encode_to(&query_bytes, QUERY_ENCODE_SET, &mut self.serialization);
        remaining
    }

    pub fn fragment_only(mut self, base_url: &Url, input: &str) -> ParseResult<Url> {
        let fragment_start = match base_url.fragment_start {
            Some(i) => i as usize,
            None => base_url.serialization.len(),
        };
        debug_assert!(self.serialization.is_empty());
        self.serialization.reserve(fragment_start + input.len());
        self.serialization.push_str(&base_url.serialization[..fragment_start]);
        self.serialization.push('#');
        debug_assert!(input.starts_with("#"));
        self.parse_fragment(&input[1..]);
        Ok(Url {
            serialization: self.serialization,
            fragment_start: Some(try!(to_u32(fragment_start))),
            ..*base_url
        })
    }

    pub fn parse_fragment(&mut self, input: &str) {
        for (i, c, next_i) in input.char_ranges() {
            match c {
                '\0' | '\t' | '\n' | '\r' => self.syntax_violation("invalid character"),
                _ => {
                    self.check_url_code_point(input, i, c);
                    utf8_percent_encode_to(
                        &input[i..next_i], SIMPLE_ENCODE_SET, &mut self.serialization);
                }
            }
        }
    }

    fn check_url_code_point(&self, input: &str, i: usize, c: char) {
        if let Some(log) = self.log_syntax_violation {
            if c == '%' {
                if !starts_with_2_hex(&input[i + 1..]) {
                    log("expected 2 hex digits after %")
                }
            } else if !is_url_code_point(c) {
                log("non-URL code point")
            }
        }
    }
}

#[inline]
fn is_ascii_hex_digit(byte: u8) -> bool {
    matches!(byte, b'a'...b'f' | b'A'...b'F' | b'0'...b'9')
}

#[inline]
fn starts_with_2_hex(input: &str) -> bool {
    input.len() >= 2
    && is_ascii_hex_digit(input.as_bytes()[0])
    && is_ascii_hex_digit(input.as_bytes()[1])
}

// Non URL code points:
// U+0000 to U+0020 (space)
// " # % < > [ \ ] ^ ` { | }
// U+007F to U+009F
// surrogates
// U+FDD0 to U+FDEF
// Last two of each plane: U+__FFFE to U+__FFFF for __ in 00 to 10 hex
#[inline]
fn is_url_code_point(c: char) -> bool {
    matches!(c,
        'a'...'z' |
        'A'...'Z' |
        '0'...'9' |
        '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | '-' |
        '.' | '/' | ':' | ';' | '=' | '?' | '@' | '_' | '~' |
        '\u{A0}'...'\u{D7FF}' | '\u{E000}'...'\u{FDCF}' | '\u{FDF0}'...'\u{FFFD}' |
        '\u{10000}'...'\u{1FFFD}' | '\u{20000}'...'\u{2FFFD}' |
        '\u{30000}'...'\u{3FFFD}' | '\u{40000}'...'\u{4FFFD}' |
        '\u{50000}'...'\u{5FFFD}' | '\u{60000}'...'\u{6FFFD}' |
        '\u{70000}'...'\u{7FFFD}' | '\u{80000}'...'\u{8FFFD}' |
        '\u{90000}'...'\u{9FFFD}' | '\u{A0000}'...'\u{AFFFD}' |
        '\u{B0000}'...'\u{BFFFD}' | '\u{C0000}'...'\u{CFFFD}' |
        '\u{D0000}'...'\u{DFFFD}' | '\u{E1000}'...'\u{EFFFD}' |
        '\u{F0000}'...'\u{FFFFD}' | '\u{100000}'...'\u{10FFFD}')
}


pub trait StrCharRanges<'a> {
    fn char_ranges(&self) -> CharRanges<'a>;
}

impl<'a> StrCharRanges<'a> for &'a str {
    #[inline]
    fn char_ranges(&self) -> CharRanges<'a> {
        CharRanges { slice: *self, position: 0 }
    }
}

pub struct CharRanges<'a> {
    slice: &'a str,
    position: usize,
}

impl<'a> Iterator for CharRanges<'a> {
    type Item = (usize, char, usize);

    #[inline]
    fn next(&mut self) -> Option<(usize, char, usize)> {
        match self.slice[self.position..].chars().next() {
            Some(ch) => {
                let position = self.position;
                self.position = position + ch.len_utf8();
                Some((position, ch, position + ch.len_utf8()))
            }
            None => None,
        }
    }
}

/// https://url.spec.whatwg.org/#c0-controls-and-space
#[inline]
fn c0_control_or_space(ch: char) -> bool {
    ch < ' '  // U+0000 to U+0020
}

/// https://url.spec.whatwg.org/#ascii-alpha
#[inline]
fn ascii_alpha(ch: char) -> bool {
    matches!(ch, 'a'...'z' | 'A'...'Z')
}

#[inline]
fn to_u32(i: usize) -> ParseResult<u32> {
    if i <= ::std::u32::MAX as usize {
        Ok(i as u32)
    } else {
        Err(ParseError::Overflow)
    }
}

/// Wether the scheme is file:, the path has a single component, and that component
/// is a Windows drive letter
fn is_windows_drive_letter(scheme_type: SchemeType, component: &str) -> bool {
    scheme_type.is_file()
    && component.len() == 2
    && ascii_alpha(component.as_bytes()[0] as char)
    && matches!(component.as_bytes()[1], b':' | b'|')
}
