use axum::extract::State;
use sev::firmware::guest::

pub struct SevSnpState {
    fw: Mutex<Firmware
}


pub async fn handler(
    State(state): State<Arc<HandlerState>>,
    Extension(conn_info): Extension<Arc<ConnInfo>>,
    Extension(request_id): Extension<RequestId>,
    Extension(ctx): Extension<Arc<RequestCtx>>,
    request: Request,
) -> Result<Response, ErrorCause> {

}