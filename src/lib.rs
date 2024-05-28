use std::{
    collections::BTreeMap, error::Error, fmt::Display, io::{Read, Write}, net::{SocketAddr, TcpStream, ToSocketAddrs}, num::ParseIntError, string::FromUtf8Error, time::Duration
};
use rfc3986::{Authority, URI};
use native_tls::{HandshakeError, TlsConnector};

type HttpHeader = (String, String);


trait Stream: Read + Write { }
impl <T: Read + Write> Stream for T { }

impl core::fmt::Debug for dyn Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

/*
6.1 Status-Line

   The first line of a Response message is the Status-Line, consisting
   of the protocol version followed by a numeric status code and its
   associated textual phrase, with each element separated by SP
   characters. No CR or LF is allowed except in the final CRLF sequence.

       Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
*/

#[derive(Debug)]
pub struct StatusLine {
    pub code: i32,
    pub reason_phrase: String,
}

#[derive(Debug)]
pub enum ParseStatusLineError {
    InvalidCode(ParseIntError),
}

impl From<native_tls::Error> for HttpConnectionError {
    fn from(value: native_tls::Error) -> Self {
        HttpConnectionError::TLS(TLSError::Connect(value))
    }
}

impl From<HandshakeError<TcpStream>> for HttpConnectionError {
    fn from(value: HandshakeError<TcpStream>) -> Self {
        HttpConnectionError::TLS(TLSError::HandShake(value))
    }
}

impl From<ParseStatusLineError> for HttpConnectionError {
    fn from(value: ParseStatusLineError) -> Self {
        HttpConnectionError::ProtocolViolation(ProtocolViolationKind::InvalidStatusLine(value))
    }
}

#[derive(Debug)]
pub enum ProtocolViolationKind {
    CRLFCRLFNotFound,
    InvalidUTF8InHead(FromUtf8Error),
    InvalidStatusLine(ParseStatusLineError),
    InvalidContentLength(usize),
}

impl From<ParseIntError> for ParseStatusLineError {
    fn from(value: ParseIntError) -> Self {
        ParseStatusLineError::InvalidCode(value)
    }
}

impl TryFrom<&str> for StatusLine {
    type Error = ParseStatusLineError;
    fn try_from(value: &str) -> Result<StatusLine, ParseStatusLineError> {
        let split: Vec<&str> = value.splitn(3, ' ').collect();

        let code = split[1].parse::<i32>()?;
        let reason_phrase = split[2].to_string();

        Ok(StatusLine {
            code,
            reason_phrase,
        })
    }
}

#[derive(Debug)]
pub enum URIErrorKind {
    Scheme,
    Authority,
}


#[derive(Debug)]
pub enum TLSError {
    Connect(native_tls::Error),
    HandShake(native_tls::HandshakeError<TcpStream>)
}

#[derive(Debug)]
pub enum HttpConnectionError {
    URI(URIErrorKind),
    IO(std::io::Error),
    ProtocolViolation(ProtocolViolationKind),
    TLS(TLSError)
}

impl Display for HttpConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl Error for HttpConnectionError {}

impl From<std::io::Error> for HttpConnectionError {
    fn from(value: std::io::Error) -> Self {
        HttpConnectionError::IO(value)
    }
}

impl From<FromUtf8Error> for HttpConnectionError {
    fn from(value: FromUtf8Error) -> Self {
        HttpConnectionError::ProtocolViolation(ProtocolViolationKind::InvalidUTF8InHead(value))
    }
}
pub struct HttpRequest {
    method: String,
    uri: URI,
    headers: Vec<HttpHeader>,
    connect_timeout: Duration,
}

struct HttpResponseComponents {
    status: Option<StatusLine>,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
}

struct HttpConnection {
    tcp: Box<dyn Stream>,
    req: HttpRequest,
    authority: Authority,
    components: BTreeMap<String, HttpResponseComponents>
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: StatusLine,
    pub headers: Vec<HttpHeader>,
    pub content: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: &str, uri: &str) -> HttpRequest {
        let uri = URI::try_from(uri).expect(&format!("{} not a valid uri", uri));

        assert!(uri.scheme == "http" || uri.scheme == "https");

        HttpRequest {
            method: String::from(method),
            uri,
            headers: vec![],
            connect_timeout: Duration::from_secs(9),
        }
    }
}

/*
    Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
    Request-URI    = "*" | absoluteURI | abs_path | authority
    Request       = Request-Line              ; Section 5.1
                *(( general-header        ; Section 4.5
                    | request-header         ; Section 5.3
                    | entity-header ) CRLF)  ; Section 7.1
                CRLF
                [ message-body ]          ; Section 4.3
*/
fn structure_req_components(connection: &HttpConnection) -> Vec<u8> {
    let (req, authority) = (&connection.req, &connection.authority);
    let request_line = format!("{} {} HTTP/1.1", req.method, req.uri.path);

    let host_header = format!("Host: {}:{}", authority.host, authority.port);
    let connection_header = String::from("Connection: close");

    let mut headers = Vec::with_capacity(req.headers.len() + 1);
    headers.push(host_header);
    headers.push(connection_header);

    for (name, value) in &req.headers {
        let header = format!("{}: {}", name, value);
        headers.push(header);
    }

    let mut req = Vec::with_capacity(1 + headers.len());
    req.push(request_line);

    for header in headers {
        req.push(header);
    }

    let crlfs = req.len() + 1;
    let len: usize = req.iter().map(String::len).sum();
    let len = crlfs + len;

    let mut structured_data = Vec::with_capacity(len);

    for unit in req {
        structured_data.extend_from_slice(unit.as_bytes());
        structured_data.extend_from_slice(b"\r\n");
    }

    structured_data.extend_from_slice(b"\r\n");

    structured_data
}

fn index_of_slice<'a>(needle: &'a [u8], haystack: &'a [u8]) -> Option<(usize, &'a [u8])> {
    for i in 0..=haystack.len() - needle.len() {
        if haystack[i..i + needle.len()] == *needle {
            return Some((i, &haystack[i + needle.len()..]));
        }
    }
    None
}

fn tcp_read(buf: &mut [u8], tcp: &mut dyn Stream) -> Result<usize, HttpConnectionError> {
    let read = tcp.read(&mut buf[..])?;
    if read == 0 {
        return Err(HttpConnectionError::IO(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "tcp stream read returned 0."
        )));
    }
    Ok(read)
}

fn find_content_len_header(headers: &Vec<HttpHeader>) -> Option<usize> {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            return value.parse::<usize>().ok();
        }
    }

    None
}

fn recv_head(connection: HttpConnection) -> Result<HttpConnection, HttpConnectionError> {
    let mut buf = [0; 8192];
    let mut rcvd = Vec::with_capacity(8192);

    const MAX_HEAD_SIZE: usize = 65536;

    let mut tcp = connection.tcp;

    for _i in 0..3 {
        let read = tcp_read(&mut buf, &mut tcp)?;

        let head = &buf[0..read];
        rcvd.extend_from_slice(head);

        match index_of_slice(b"\r\n\r\n", &rcvd[..]) {
            Some((i, head_of_body)) => {
                let body = head_of_body.to_vec();
                let head = &rcvd[..i];

                assert!(head.len() < MAX_HEAD_SIZE);

                let head = String::from_utf8(head.to_vec())?;


                let comp = HttpResponseComponents {
                    status: None,
                    headers: Vec::with_capacity(13),
                    body,
                };
                let mut components = connection.components;
                components.insert(head, comp);

                return Ok(HttpConnection {
                    tcp,
/*                     heads, */
                    components,
                    ..connection
                });
            }
            None => continue,
        }
    }

    Err(HttpConnectionError::ProtocolViolation(
        ProtocolViolationKind::CRLFCRLFNotFound,
    ))
}

fn parse_head(connection: HttpConnection) -> Result<HttpConnection, HttpConnectionError> {
    let mut components = connection.components;
    let (head, mut present) = components
        .pop_last()
        .unwrap();

    let split: Vec<&str> = head
        .split("\r\n")
        .collect();

    /*
            generic-message = start-line
                              *(message-header CRLF)
                              CRLF
                              [ message-body ]
            start-line      = Request-Line | Status-Line
    */

    let status_line = StatusLine::try_from(split[0])?;
    present.status = Some(status_line);

    if split.len() > 1 {
        let headers = &split[1..];
        for &header in headers {
            let pair: Vec<&str> = header.splitn(2, ':').collect();
            let (name, value) = (pair[0].trim(), pair[1].trim());
            present
                .headers
                .push((String::from(name), String::from(value)));
        }
    }

    components.insert(head, present);

    Ok(HttpConnection {
        components,
        ..connection
    })
}

/*
4.4 Message Length

   The transfer-length of a message is the length of the message-body as
   it appears in the message; that is, after any transfer-codings have
   been applied. When a message-body is included with a message, the
   transfer-length of that body is determined by one of the following
   (in order of precedence):

   1.Any response message which "MUST NOT" include a message-body (such
     as the 1xx, 204, and 304 responses and any response to a HEAD
     request) is always terminated by the first empty line after the
     header fields, regardless of the entity-header fields present in
     the message.

   2.If a Transfer-Encoding header field (section 14.41) is present and
     has any value other than "identity", then the transfer-length is
     defined by use of the "chunked" transfer-coding (section 3.6),
     unless the message is terminated by closing the connection.

   3.If a Content-Length header field (section 14.13) is present, its
     decimal value in OCTETs represents both the entity-length and the
     transfer-length. The Content-Length header field MUST NOT be sent
     if these two lengths are different (i.e., if a Transfer-Encoding
 header field is present). If a message is received with both a
     Transfer-Encoding header field and a Content-Length header field,
     the latter MUST be ignored.

   4.If the message uses the media type "multipart/byteranges", and the
     ransfer-length is not otherwise specified, then this self-
     elimiting media type defines the transfer-length. This media type
     UST NOT be used unless the sender knows that the recipient can arse
     it; the presence in a request of a Range header with ultiple byte-
     range specifiers from a 1.1 client implies that the lient can parse
     multipart/byteranges responses.

       A range header might be forwarded by a 1.0 proxy that does not
       understand multipart/byteranges; in this case the server MUST
       delimit the message using methods defined in items 1,3 or 5 of
       this section.

   5.By the server closing the connection. (Closing the connection
     cannot be used to indicate the end of a request body, since that
     would leave no possibility for the server to send back a response.)

   For compatibility with HTTP/1.0 applications, HTTP/1.1 requests
   containing a message-body MUST include a valid Content-Length header
   field unless the server is known to be HTTP/1.1 compliant. If a
   request contains a message-body and a Content-Length is not given,
   the server SHOULD respond with 400 (bad request) if it cannot
   determine the length of the message, or with 411 (length required) if
   it wishes to insist on receiving a valid Content-Length.

   All HTTP/1.1 applications that receive entities MUST accept the
   "chunked" transfer-coding (section 3.6), thus allowing this mechanism
   to be used for messages when the message length cannot be determined
   in advance.

   Messages MUST NOT include both a Content-Length header field and a
   non-identity transfer-coding. If the message does include a non-
   identity transfer-coding, the Content-Length MUST be ignored.

   When a Content-Length is given in a message where a message-body is
   allowed, its field value MUST exactly match the number of OCTETs in
   the message-body. HTTP/1.1 user agents MUST notify the user when an
   invalid length is received and detected.
*/
fn recv_body(connection: HttpConnection) -> Result<HttpConnection, HttpConnectionError> {
    let mut components = connection.components;
    let mut entry = components
        .last_entry()
        .unwrap();
    let present = entry.get_mut();
    let content_len = match find_content_len_header(&present.headers) {
        Some(content_len) => content_len,
        None => unimplemented!(),
    };

    let present_len = present.body.len();
    if content_len < present_len {
        return Err(HttpConnectionError::ProtocolViolation(
            ProtocolViolationKind::InvalidContentLength(content_len),
        ));
    }

    assert!(content_len < 1073741824);

    let bytes_left = content_len - present_len;
    let mut buf: [u8; 65536] = [0; 65536];
    let mut tcp = connection.tcp;

    let mut ttl = 0;
    while ttl < bytes_left {
        ttl += tcp_read(&mut buf, &mut tcp)?;
        present.body.extend_from_slice(&buf[..ttl]);
    }

    Ok(HttpConnection {
        tcp,
        components,
        ..connection
    })
}

/*
    Response      = Status-Line               ; Section 6.1
                    *(( general-header        ; Section 4.5
                    | response-header        ; Section 6.2
                    | entity-header ) CRLF)  ; Section 7.1
                    CRLF
                    [ message-body ]          ; Section 7.2

*/
fn send_req(connection: HttpConnection) -> Result<HttpConnection, HttpConnectionError> {
    let structured_req_data = structure_req_components(&connection);
    let mut tcp = connection.tcp;
    tcp.write_all(&structured_req_data[..])?;
    Ok(HttpConnection { tcp, ..connection })
}

fn connect(req: HttpRequest) -> Result<HttpConnection, HttpConnectionError> {
    let authority = req.uri.authority
        .clone()
        .unwrap();

    let host_port = format!("{}:{}", authority.host, authority.port);

    let sock_addr: Vec<SocketAddr> = host_port
        .to_socket_addrs()?
        .collect();

    let addr = sock_addr[0];

    let tcp = TcpStream::connect_timeout(&addr, req.connect_timeout)?;


    let tcp: Box<dyn Stream> =
        match &req.uri.scheme[..] {
            "https" => {
                let negotiator = TlsConnector::new()?;
                let tls_stream = negotiator.connect(&authority.host, tcp)?;
                Box::new(tls_stream)
            },
            "http" => Box::new(tcp),
            _ => unreachable!()
        };

    Ok(HttpConnection {
        tcp,
        req,
        /* heads: Vec::with_capacity(3), */
        authority,
        /* components: Vec::with_capacity(3), */
        components: BTreeMap::new()
    })
}

pub fn retrieve_response(req: HttpRequest) -> Result<HttpResponse, HttpConnectionError> {

    let connection = connect(req)?;
    let connection = send_req(connection)?;

    let connection = recv_head(connection)?;
    let connection = parse_head(connection)?;

    let connection = recv_body(connection)?;

    let mut components = connection.components;
    let (_, present) =  components
        .pop_last()
        .unwrap();

    Ok(HttpResponse {
        status: present.status.unwrap(),
        headers: present.headers,
        content: present.body
    })
}

#[cfg(test)]
mod tests {
    use crate::{retrieve_response, HttpConnectionError, HttpRequest};

    #[test]
    fn exec() -> Result<(), HttpConnectionError> {
        let req = HttpRequest::new("GET", "http://httpbin.org/get?abc#123");
        let response = retrieve_response(req)?;
        assert_eq!(response.status.code, 200);
        Ok(())
    }
}
