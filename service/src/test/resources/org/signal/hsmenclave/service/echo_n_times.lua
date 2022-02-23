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

times = 1

function HandleChannelMessage(cid, msg)
  out = {}
  for i=1,times do
    table.insert(out, {cid,msg..times})
  end
  times = times + 1
  return out
end
