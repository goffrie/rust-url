use encoding::EncodingOverride;
use std::cmp;
use std::fmt;
use std::hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::{Range, RangeFrom, RangeTo};

#[test]
fn size() {
    assert_eq!(::std::mem::size_of::<Url>(), 88);
}

/// A parsed URL record.
#[derive(Clone)]
pub struct Url {
    serialization: String,
    non_relative: bool,

    // Components
    scheme_end: u32,  // Before ':'
    username_end: u32,
    host_range: Range<u32>,
    host: HostInternal,
    port: Option<u16>,
    path_start: u32,  // Before initial '/' if !non_relative
    query_start: Option<u32>,  // Before '?'
    fragment_start: Option<u32>,  // Before '#'
}

#[derive(Clone)]
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
        Url::parse_with(input, None, EncodingOverride::utf8())
    }

    /// Parse a string as an URL, with this URL as the base URL.
    #[inline]
    pub fn join(&self, input: &str) -> Result<Url, ::ParseError> {
        Url::parse_with(input, Some(self), EncodingOverride::utf8())
    }

    /// The URL parser with all of its parameters.
    ///
    /// `encoding_override` is a legacy concept only relevant for HTML.
    /// When it’s not needed,
    /// `s.parse::<Url>()`, `Url::from_str(s)` and `url.join(s)` can be used instead.
    pub fn parse_with(input: &str, base_url: Option<&Url>,
                      encoding_override: EncodingOverride) -> Result<Url, ::ParseError> {
        unimplemented!();
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
        if self.byte_at(self.username_end) == b':' {
            debug_assert!(self.has_host());
            let password_end = self.host_range.start - 1;
            debug_assert!(self.byte_at(password_end) == b'@');
            Some(self.slice(self.username_end + 1..password_end))
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
            Some(self.slice(self.host_range.clone()))
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
            HostInternal::Domain => Some(Host::Domain(self.slice(self.host_range.clone()))),
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

    /// Return the serialization of this URL without any fragment identifier.
    pub fn without_fragment(&self) -> &str {
        match self.fragment_start {
            Some(fragment_start) => self.slice(..fragment_start),
            None => &self.serialization
        }
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
        let host = url.slice(url.host_range.clone());
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
            debug_assert!(url.byte_at(url.host_range.end) == b':');
            url.slice(url.host_range.end + 1..url.path_start)
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

impl Url {
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
