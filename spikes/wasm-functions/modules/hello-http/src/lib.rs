use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct Component;

wasi::http::proxy::export!(Component);

impl wasi::exports::http::incoming_handler::Guest for Component {
    fn handle(_request: IncomingRequest, response_out: ResponseOutparam) {
        let resp = OutgoingResponse::new(Fields::new());
        resp.set_status_code(200).unwrap();
        let body = resp.body().unwrap();
        ResponseOutparam::set(response_out, Ok(resp));
        let out = body.write().unwrap();
        out.blocking_write_and_flush(b"hello from wasm\n").unwrap();
        drop(out);
        OutgoingBody::finish(body, None).unwrap();
    }
}
