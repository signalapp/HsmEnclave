--
-- Copyright 2022 Signal Messenger, LLC
-- SPDX-License-Identifier: AGPL-3.0-only
--
kk = 0

function HandleChannelCreate(cid, typ)
    if typ == CHAN_SERVER_KK then
        kk = cid
    end
end

function HandleChannelClose(cid) end

function HandleChannelMessage(cid, msg)
    if msg == "ping" then
        return {{kk, string.pack("c1 >I4", "P", cid)}}
    elseif msg:sub(1,1) == "P" then
        return {{cid, "X" .. msg:sub(2)}}
    elseif msg:sub(1,1) == "X" then
        local out = string.unpack(">I4", msg, 2)
        return {{out, "pong"}, {out, STATUS_OK}}
    end
end
