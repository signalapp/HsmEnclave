--
-- Copyright 2022 Signal Messenger, LLC
-- SPDX-License-Identifier: AGPL-3.0-only
--
unencrypted = 0
kk = 0

function HandleChannelCreate(cid, typ)
    if typ == CHAN_UNENCRYPTED then
        unencrypted = cid
    elseif typ == CHAN_SERVER_KK then
        kk = cid
    else
        error("unexpected channel type")
    end
end

function HandleChannelClose(cid) end

function HandleChannelMessage(cid, msg)
    if cid == unencrypted then
        return {{kk, msg}}
    end
    return {{unencrypted, msg}}
end
