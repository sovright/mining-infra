use zcash_mining_protocol::{
    codec::{decode_new_equihash_job, decode_set_target, decode_submit_shares_response, MessageFrame},
    messages::{message_types, NewEquihashJob, SetTarget, SubmitSharesResponse},
};

pub enum ServerMessage {
    NewJob(NewEquihashJob),
    ShareResponse(SubmitSharesResponse),
    SetTarget(SetTarget),
}

pub fn decode_server_message(data: &[u8]) -> Result<ServerMessage, String> {
    let frame = MessageFrame::decode(data).map_err(|e| format!("frame decode: {e}"))?;

    match frame.msg_type {
        message_types::NEW_EQUIHASH_JOB => {
            let job = decode_new_equihash_job(data).map_err(|e| format!("job decode: {e}"))?;
            Ok(ServerMessage::NewJob(job))
        }
        message_types::SUBMIT_SHARES_RESPONSE => {
            let resp =
                decode_submit_shares_response(data).map_err(|e| format!("response decode: {e}"))?;
            Ok(ServerMessage::ShareResponse(resp))
        }
        message_types::SET_TARGET => {
            let target = decode_set_target(data).map_err(|e| format!("set_target decode: {e}"))?;
            Ok(ServerMessage::SetTarget(target))
        }
        other => Err(format!("unknown message type: 0x{other:02x}")),
    }
}
