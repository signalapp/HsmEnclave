--
-- Copyright 2022 Signal Messenger, LLC
-- SPDX-License-Identifier: AGPL-3.0-only
--
function HandleChannelCreate(cid)
  return {}
end

function HandleChannelClose(cid)
  return {}
end

function HandleChannelMessage(cid, msg)
    b = msg:byte(1)
    return {{cid, "status=" .. b}, {cid, b}}
end
