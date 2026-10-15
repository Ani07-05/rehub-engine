@load packages
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_EPOCH;
@load policy/protocols/conn/community-id-logging
