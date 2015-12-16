// Copyright 2013-2015 Simon Sapin.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!

<a href="https://github.com/servo/rust-url"><img style="position: absolute; top: 0; left: 0; border: 0;" src="../github.png" alt="Fork me on GitHub"></a>
<style>.sidebar { margin-top: 53px }</style>

rust-url is an implementation of the [URL Standard](http://url.spec.whatwg.org/)
for the [Rust](http://rust-lang.org/) programming language.

It builds with [Cargo](http://crates.io/).
To use it in your project, add this to your `Cargo.toml` file:

```Cargo
[dependencies.url]
git = "https://github.com/servo/rust-url"
```

Supporting encodings other than UTF-8 in query strings is an optional feature
that requires [rust-encoding](https://github.com/lifthrasiir/rust-encoding)
and is off by default.
You can enable it with
[Cargo’s *features* mechanism](http://doc.crates.io/manifest.html#the-[features]-section):

```Cargo
[dependencies.url]
git = "https://github.com/servo/rust-url"
features = ["query_encoding"]
```

… or by passing `--cfg 'feature="query_encoding"'` to rustc.


# URL parsing and data structures

First, URL parsing may fail for various reasons and therefore returns a `Result`.

```
use url::{Url, ParseError};

assert!(Url::parse("http://[:::1]") == Err(ParseError::InvalidIpv6Address))
```

Let’s parse a valid URL and look at its components.

```
use url::{Url, SchemeData};

let issue_list_url = Url::parse(
    "https://github.com/rust-lang/rust/issues?labels=E-easy&state=open"
).unwrap();


assert!(issue_list_url.scheme == "https".to_string());
assert!(issue_list_url.domain() == Some("github.com"));
assert!(issue_list_url.port() == None);
assert!(issue_list_url.path() == Some(&["rust-lang".to_string(),
                                        "rust".to_string(),
                                        "issues".to_string()][..]));
assert!(issue_list_url.query == Some("labels=E-easy&state=open".to_string()));
assert!(issue_list_url.fragment == None);
match issue_list_url.scheme_data {
    SchemeData::Relative(..) => {},  // Expected
    SchemeData::NonRelative(..) => panic!(),
}
```

The `scheme`, `query`, and `fragment` are directly fields of the `Url` struct:
they apply to all URLs.
Every other components has accessors because they only apply to URLs said to be
“in a relative scheme”. `https` is a relative scheme, but `data` is not:

```
use url::{Url, SchemeData};

let data_url = Url::parse("data:text/plain,Hello#").unwrap();

assert!(data_url.scheme == "data".to_string());
assert!(data_url.scheme_data == SchemeData::NonRelative("text/plain,Hello".to_string()));
assert!(data_url.non_relative_scheme_data() == Some("text/plain,Hello"));
assert!(data_url.query == None);
assert!(data_url.fragment == Some("".to_string()));
```


# Base URL

Many contexts allow URL *references* that can be relative to a *base URL*:

```html
<link rel="stylesheet" href="../main.css">
```

Since parsed URL are absolute, giving a base is required:

```
use url::{Url, ParseError};

assert!(Url::parse("../main.css") == Err(ParseError::RelativeUrlWithoutBase))
```

`UrlParser` is a method-chaining API to provide various optional parameters
to URL parsing, including a base URL.

```
use url::{Url, UrlParser};

let this_document = Url::parse("http://servo.github.io/rust-url/url/index.html").unwrap();
let css_url = UrlParser::new().base_url(&this_document).parse("../main.css").unwrap();
assert!(css_url.serialize() == "http://servo.github.io/rust-url/main.css".to_string());
```

For convenience, the `join` method on `Url` is also provided to achieve the same result:

```
use url::Url;

let this_document = Url::parse("http://servo.github.io/rust-url/url/index.html").unwrap();
let css_url = this_document.join("../main.css").unwrap();
assert!(&*css_url.serialize() == "http://servo.github.io/rust-url/main.css")
*/

#![cfg_attr(feature="heap_size", feature(plugin, custom_derive))]
#![cfg_attr(feature="heap_size", plugin(heapsize_plugin))]

extern crate rustc_serialize;
extern crate uuid;
#[macro_use] extern crate matches;
#[cfg(feature="serde_serialization")] extern crate serde;
#[cfg(feature="heap_size")] #[macro_use] extern crate heapsize;

extern crate unicode_normalization;
extern crate unicode_bidi;

use std::path::{Path, PathBuf};
use std::borrow::Borrow;

use std::cmp;
use std::fmt;
use std::hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::{Range, RangeFrom, RangeTo, RangeFull, Index};

use percent_encoding::{percent_encode, lossy_utf8_percent_decode, DEFAULT_ENCODE_SET};
pub use encoding::EncodingOverride;
use uuid::Uuid;
pub use parser::ParseError;

mod encoding;
mod host;
mod parser;
pub mod percent_encoding;
pub mod form_urlencoded;
pub mod punycode;
pub mod idna;
mod idna_mapping;

/// A parsed URL record.
#[derive(Clone)]
pub struct Url {
    serialization: String,
    non_relative: bool,

    // Components
    scheme_end: u32,  // Before ':'
    username_end: u32,
    host_start: u32,
    host_end: u32,
    host: HostInternal,
    port: Option<u16>,
    path_start: u32,  // Before initial '/' if !non_relative
    query_start: Option<u32>,  // Before '?', unlike Position::QueryStart
    fragment_start: Option<u32>,  // Before '#', unlike Position::FragmentStart
}

#[derive(Copy, Clone)]
enum HostInternal {
    None,
    Domain,
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Host<'a> {
    /// A DNS domain name, as '.' dot-separated labels.
    /// Non-ASCII labels are encoded in punycode per IDNA.
    Domain(&'a str),

    /// An IPv4 address.
    Ipv4(Ipv4Addr),

    /// An IPv6 address.
    Ipv6(Ipv6Addr),
}

impl Url {
    /// Parse an absolute URL from a string.
    #[inline]
    pub fn parse(input: &str) -> Result<Url, ::ParseError> {
        Url::parse_with(input, None, EncodingOverride::utf8(), None)
    }

    /// Parse a string as an URL, with this URL as the base URL.
    #[inline]
    pub fn join(&self, input: &str) -> Result<Url, ::ParseError> {
        Url::parse_with(input, Some(self), EncodingOverride::utf8(), None)
    }

    /// The URL parser with all of its parameters.
    ///
    /// `encoding_override` is a legacy concept only relevant for HTML.
    /// When it’s not needed,
    /// `s.parse::<Url>()`, `Url::from_str(s)` and `url.join(s)` can be used instead.
    pub fn parse_with(input: &str,
                      base_url: Option<&Url>,
                      encoding_override: EncodingOverride,
                      log_syntax_violation: Option<&Fn(&'static str)>)
                      -> Result<Url, ::ParseError> {
        parser::Parser {
            serialization: String::with_capacity(input.len()),
            base_url: base_url,
            query_encoding_override: EncodingOverride,
            log_syntax_violation: log_syntax_violation,
        }.parse_url(input)
    }

    /// Return the scheme of this URL, as an ASCII string without the ':' delimiter.
    #[inline]
    pub fn scheme(&self) -> &str {
        self.slice(..self.scheme_end)
    }

    /// Return whether this URL is non-relative (typical of e.g. `data:` and `mailto:` URLs.)
    #[inline]
    pub fn non_relative(&self) -> bool {
        self.non_relative
    }

    /// Return the username for this URL (typically the empty string)
    /// as a percent-encoded ASCII string.
    pub fn username(&self) -> &str {
        if self.non_relative {
            ""
        } else {
            debug_assert!(self.slice(self.scheme_end..self.scheme_end + 3) == "://");
            self.slice(self.scheme_end + 3..self.username_end)
        }
    }

    /// Return the password for this URL, if any, as a percent-encoded ASCII string.
    pub fn password(&self) -> Option<&str> {
        if self.port.is_some() {
            debug_assert!(self.has_host());
            debug_assert!(self.byte_at(self.username_end) == b':');
            debug_assert!(self.byte_at(self.host_start - 1) == b'@');
            Some(self.slice(self.username_end + 1..self.host_start - 1))
        } else {
            None
        }
    }

    /// Return whether this URL has a host.
    ///
    /// Non-relative URLs (typical of `data:` and `mailto:`) and some `file:` URLs don’t.
    #[inline]
    pub fn has_host(&self) -> bool {
        !matches!(self.host, HostInternal::None)
    }

    /// Return the string representation of the host (domain or IP address) for this URL, if any.
    /// Non-ASCII domains are punycode-encoded per IDNA.
    ///
    /// Non-relative URLs (typical of `data:` and `mailto:`) and some `file:` URLs
    /// don’t have a host.
    pub fn host_str(&self) -> Option<&str> {
        if self.has_host() {
            Some(self.slice(self.host_start..self.host_end))
        } else {
            None
        }
    }

    /// Return the parsed representation of the host for this URL.
    /// Non-ASCII domain labels are punycode-encoded per IDNA.
    ///
    /// Non-relative URLs (typical of `data:` and `mailto:`) and some `file:` URLs
    /// don’t have a host.
    pub fn host(&self) -> Option<Host> {
        match self.host {
            HostInternal::None => None,
            HostInternal::Domain => Some(Host::Domain(self.slice(self.host_start..self.host_end))),
            HostInternal::Ipv4(address) => Some(Host::Ipv4(address)),
            HostInternal::Ipv6(address) => Some(Host::Ipv6(address)),
        }
    }

    /// Return the port number for this URL, if any.
    #[inline]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Return the path for this URL, as a percent-encoded ASCII string.
    /// For relative URLs, this starts with a '/' slash
    /// and continues with slash-separated path components.
    /// For non-relative URLs, this is an arbitrary string that doesn’t start with '/'.
    pub fn path(&self) -> &str {
        match (self.query_start, self.fragment_start) {
            (None, None) => self.slice(self.path_start..),
            (Some(next_component_start), _) |
            (None, Some(next_component_start)) => {
                self.slice(self.path_start..next_component_start)
            }
        }
    }

    /// If this URL is relative, return an iterator of '/' slash-separated path components,
    /// each as a percent-encoded ASCII string.
    pub fn path_components(&self) -> Option<::std::str::Split<char>> {
        if self.non_relative {
            None
        } else {
            let path = self.path();
            debug_assert!(path.starts_with("/"));
            Some(path[1..].split('/'))
        }
    }

    /// Return this URL’s query string, if any, as a percent-encoded ASCII string.
    pub fn query(&self) -> Option<&str> {
        match (self.query_start, self.fragment_start) {
            (None, _) => None,
            (Some(query_start), None) => Some(self.slice(query_start..)),
            (Some(query_start), Some(fragment_start)) => {
                debug_assert!(self.byte_at(query_start) == b'?');
                Some(self.slice(query_start + 1..fragment_start))
            }
        }
    }

    /// Return this URL’s fragment identifier, if any, as a percent-encoded ASCII string.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment_start.map(|start| {
            debug_assert!(self.byte_at(start) == b'#');
            self.slice(start + 1..)
        })
    }
}

/// https://url.spec.whatwg.org/#api
///
/// Not represented:
/// * https://url.spec.whatwg.org/#dom-url-href
///   * Getter: `url.as_ref()`
///   * Setter: `Url::parse()`
pub struct Idl;

impl Idl {
    /// https://url.spec.whatwg.org/#dom-url-domaintoascii
    pub fn domain_to_ascii(domain: &str) -> String {
        unimplemented!()  // FIXME
    }

    /// https://url.spec.whatwg.org/#dom-url-domaintounicode
    pub fn domain_to_unicode(domain: &str) -> String {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-origin
    pub fn get_origin(url: &Url) -> String {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-protocol
    #[inline]
    pub fn get_protocol(url: &Url) -> &str {
        debug_assert!(url.byte_at(url.scheme_end) == b':');
        url.slice(..url.scheme_end + 1)
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-protocol
    pub fn set_protocol(url: &mut Url, new_protocol: &str) {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-username
    #[inline]
    pub fn get_username(url: &Url) -> &str {
        url.username()
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-username
    pub fn set_username(url: &mut Url, new_username: &str) {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-password
    #[inline]
    pub fn get_password(url: &Url) -> &str {
        url.password().unwrap_or("")
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-password
    pub fn set_password(url: &mut Url, new_password: &str) {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-host
    #[inline]
    pub fn get_host(url: &Url) -> &str {
        let host = url.slice(url.host_start..url.host_end);
        debug_assert!(!host.is_empty() || url.non_relative);
        host
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-host
    pub fn set_host(url: &mut Url, new_host: &str) {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-hostname
    #[inline]
    pub fn get_hostname(url: &Url) -> &str {
        url.host_str().unwrap_or("")
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-hostname
    pub fn set_hostname(url: &mut Url, new_hostname: &str) {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-port
    #[inline]
    pub fn get_port(url: &Url) -> &str {
        if url.port.is_some() {
            debug_assert!(url.byte_at(url.host_end) == b':');
            url.slice(url.host_end + 1..url.path_start)
        } else {
            ""
        }
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-port
    pub fn set_port(url: &mut Url, new_port: &str) {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-pathname
    #[inline]
    pub fn get_pathname(url: &Url) -> &str {
         url.path()
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-pathname
    pub fn set_pathname(url: &mut Url, new_pathname: &str) {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-search
    pub fn get_search(url: &Url) -> &str {
        match (url.query_start, url.fragment_start) {
            (None, _) => "",
            (Some(query_start), None) => url.slice(query_start..),
            (Some(query_start), Some(fragment_start)) => {
                url.slice(query_start..fragment_start)
            }
        }
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-search
    pub fn set_search(url: &mut Url, new_search: &str) {
        unimplemented!()  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-searchparams
    pub fn get_search_params(url: &Url) -> Vec<(String, String)> {
        unimplemented!();  // FIXME
    }

    /// Getter for https://url.spec.whatwg.org/#dom-url-hash
    pub fn get_hash(url: &Url) -> &str {
        match url.fragment_start {
            Some(start) => url.slice(start..),
            None => "",
        }
    }

    /// Setter for https://url.spec.whatwg.org/#dom-url-hash
    pub fn set_hash(url: &mut Url, new_hash: &str) {
        unimplemented!()  // FIXME
    }
}

/// Parse a string as an URL, without a base URL or encoding override.
impl ::std::str::FromStr for Url {
    type Err = ::ParseError;

    #[inline]
    fn from_str(input: &str) -> Result<Url, ::ParseError> {
        Url::parse(input)
    }
}

/// Display the serialization of this URL.
impl fmt::Display for Url {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.serialization, formatter)
    }
}

/// Debug the serialization of this URL.
impl fmt::Debug for Url {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.serialization, formatter)
    }
}

/// URLs compare like their serialization.
impl Eq for Url {}

/// URLs compare like their serialization.
impl PartialEq for Url {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.serialization == other.serialization
    }
}

/// URLs compare like their serialization.
impl Ord for Url {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.serialization.cmp(&other.serialization)
    }
}

/// URLs compare like their serialization.
impl PartialOrd for Url {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.serialization.partial_cmp(&other.serialization)
    }
}

/// URLs hash like their serialization.
impl hash::Hash for Url {
    #[inline]
    fn hash<H>(&self, state: &mut H) where H: hash::Hasher {
        hash::Hash::hash(&self.serialization, state)
    }
}

/// Return the serialization of this URL.
impl AsRef<str> for Url {
    #[inline]
    fn as_ref(&self) -> &str {
        self.serialization.as_ref()
    }
}

impl Index<RangeFull> for Url {
    type Output = str;
    fn index(&self, _: RangeFull) -> &str {
        &self.serialization
    }
}

impl Index<RangeFrom<Position>> for Url {
    type Output = str;
    fn index(&self, range: RangeFrom<Position>) -> &str {
        &self.serialization[self.index(range.start)..]
    }
}

impl Index<RangeTo<Position>> for Url {
    type Output = str;
    fn index(&self, range: RangeTo<Position>) -> &str {
        &self.serialization[..self.index(range.end)]
    }
}

impl Index<Range<Position>> for Url {
    type Output = str;
    fn index(&self, range: Range<Position>) -> &str {
        &self.serialization[self.index(range.start)..self.index(range.end)]
    }
}

/// Indicates a position within a URL based on its components.
///
/// A range of positions can be used for slicing `Url`:
///
/// ```rust
/// let serialization: &str = &some_url[..];
/// let serialization_without_fragment: &str = &some_url[..Position::QueryEnd];
/// let authority: &str = &some_url[Position::UsernameStart..Position::PortEnd];
/// let data_url_payload: &str = &some_url[Position::PathStart..Position::QueryEnd];
/// let scheme_relative: &str = &some_url[Position::UsernameStart..];
/// ```
///
/// In a pseudo-grammar (where `[`…`]?` makes a sub-sequence optional),
/// URL components and delimiters that separate them are:
///
/// ```notrust
/// url =
///     scheme ":"
///     [ "//" [ username [ ":" password ]? "@" ]? host [ ":" port ]? ]
///     path [ "?" query ]? [ "#" fragment ]?
/// ```
///
/// When a given component is not present,
/// its "start" and "end" position are the same
/// (so that `&some_url[FooStart..FooEnd]` is the empty string)
/// and component ordering is preserved
/// (so that a missing query "is between" a path and a fragment).
///
/// The end of a component and the start of the next are either the same or separate
/// by a delimiter.
/// (Not that the initial `/` of a path is considered part of the path here, not a delimiter.)
/// For example, `&url[..FragmentStart]` would include a `#` delimiter (if present in `url`),
/// so `&url[..QueryEnd]` might be desired instead.
///
/// `SchemeStart` and `FragmentEnd` are always the start and end of the entire URL,
/// so `&url[SchemeStart..X]` is the same as `&url[..X]`
/// and `&url[X..FragmentEnd]` is the same as `&url[X..]`.
pub enum Position {
    SchemeStart,
    SchemeEnd,
    UsernameStart,
    UsernameEnd,
    PasswordStart,
    PasswordEnd,
    HostStart,
    HostEnd,
    PortStart,
    PortEnd,
    PathStart,
    PathEnd,
    QueryStart,
    QueryEnd,
    FragmentStart,
    FragmentEnd
}

impl Url {
    #[inline]
    fn index(&self, position: Position) -> usize {
        match position {
            Position::SchemeStart => 0,

            Position::SchemeEnd => self.scheme_end as usize,

            Position::UsernameStart => if self.non_relative {
                debug_assert!(self.byte_at(self.scheme_end) == b':');
                debug_assert!(self.scheme_end + ":".len() as u32 == self.username_end);
                self.scheme_end as usize + ":".len()
            } else {
                debug_assert!(self.slice(self.scheme_end..).starts_with("://"));
                self.scheme_end as usize + "://".len()
            },

            Position::UsernameEnd => self.username_end as usize,

            Position::PasswordStart => if self.port.is_some() {
                debug_assert!(self.has_host());
                debug_assert!(self.byte_at(self.username_end) == b':');
                self.username_end as usize + ":".len()
            } else {
                debug_assert!(self.username_end == self.host_start);
                self.username_end as usize
            },

            Position::PasswordEnd => if self.port.is_some() {
                debug_assert!(self.has_host());
                debug_assert!(self.byte_at(self.username_end) == b':');
                debug_assert!(self.byte_at(self.host_start - "@".len() as u32) == b'@');
                self.host_start as usize - "@".len()
            } else {
                debug_assert!(self.username_end == self.host_start);
                self.host_start as usize
            },

            Position::HostStart => self.host_start as usize,

            Position::HostEnd => self.host_end as usize,

            Position::PortStart => if self.port.is_some() {
                debug_assert!(self.byte_at(self.host_end) == b':');
                self.host_end as usize + ":".len()
            } else {
                self.host_end as usize
            },

            Position::PortEnd => self.path_start as usize,

            Position::PathStart => self.path_start as usize,

            Position::PathEnd => match (self.query_start, self.fragment_start) {
                (Some(q), _) => q as usize,
                (None, Some(f)) => f as usize,
                (None, None) => self.serialization.len(),
            },

            Position::QueryStart => match (self.query_start, self.fragment_start) {
                (Some(q), _) => {
                    debug_assert!(self.byte_at(q) == b'?');
                    q as usize + "?".len()
                }
                (None, Some(f)) => f as usize,
                (None, None) => self.serialization.len(),
            },

            Position::QueryEnd => match self.fragment_start {
                None => self.serialization.len(),
                Some(f) => f as usize,
            },

            Position::FragmentStart => match self.fragment_start {
                Some(f) => {
                    debug_assert!(self.byte_at(f) == b'#');
                    f as usize + "#".len()
                }
                None => self.serialization.len(),
            },

            Position::FragmentEnd => self.serialization.len(),
        }
    }

    #[inline]
    fn slice<R>(&self, range: R) -> &str where R: RangeArg {
        range.slice_of(&self.serialization)
    }

    #[inline]
    fn byte_at(&self, i: u32) -> u8 {
        self.serialization.as_bytes()[i as usize]
    }
}

trait RangeArg {
    fn slice_of<'a>(&self, s: &'a str) -> &'a str;
}

impl RangeArg for Range<u32> {
    #[inline]
    fn slice_of<'a>(&self, s: &'a str) -> &'a str {
        &s[self.start as usize .. self.end as usize]
    }
}

impl RangeArg for RangeFrom<u32> {
    #[inline]
    fn slice_of<'a>(&self, s: &'a str) -> &'a str {
        &s[self.start as usize ..]
    }
}

impl RangeArg for RangeTo<u32> {
    #[inline]
    fn slice_of<'a>(&self, s: &'a str) -> &'a str {
        &s[.. self.end as usize]
    }
}

impl rustc_serialize::Encodable for Url {
    fn encode<S: rustc_serialize::Encoder>(&self, encoder: &mut S) -> Result<(), S::Error> {
        encoder.emit_str(self.as_ref())
    }
}


impl rustc_serialize::Decodable for Url {
    fn decode<D: rustc_serialize::Decoder>(decoder: &mut D) -> Result<Url, D::Error> {
        Url::parse(&*try!(decoder.read_str())).map_err(|error| {
            decoder.error(&format!("URL parsing error: {}", error))
        })
    }
}

/// Serializes this URL into a `serde` stream.
///
/// This implementation is only available if the `serde_serialization` Cargo feature is enabled.
#[cfg(feature="serde_serialization")]
impl serde::Serialize for Url {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error> where S: serde::Serializer {
        format!("{}", self).serialize(serializer)
    }
}

/// Deserializes this URL from a `serde` stream.
///
/// This implementation is only available if the `serde_serialization` Cargo feature is enabled.
#[cfg(feature="serde_serialization")]
impl serde::Deserialize for Url {
    fn deserialize<D>(deserializer: &mut D) -> Result<Url, D::Error> where D: serde::Deserializer {
        let string_representation: String = try!(serde::Deserialize::deserialize(deserializer));
        Ok(Url::parse(&string_representation).unwrap())
    }
}
