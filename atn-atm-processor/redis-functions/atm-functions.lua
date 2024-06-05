#!lua name=atm

-- store_message
-- keys = message_hash
-- args = [1] message
--        [2] message length in bytes
--        [3] to_did
--        [4] to_did_hash
--        [5] from_did
--        [6] from_did_hash
local function store_message(keys, args)
    -- Do we have the correct number of arguments?
    -- from_did_hash can be optional!!!
    if #args < 5  then
        return redis.error_reply('store_message: not enough arguments')
    elseif #args > 6 then
        return redis.error_reply('store_message: too many arguments')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Get current time on server
    local time = redis.call('TIME')[1]
    local bytes = tonumber(args[2])
    if bytes == nil then
        return redis.error_reply('store_message: invalid bytes')
    end
    
    -- Store message
    redis.call('SET', 'MSG:'..keys[1], args[1])

    -- Set Global Metrics
    redis.call('HINCRBY', 'GLOBAL', 'RECEIVED_BYTES', bytes)
    redis.call('HINCRBY', 'GLOBAL', 'RECEIVED_COUNT', 1)

    -- Create Message Expiry Record
    redis.call('RPUSH', 'MSG_EXPIRY', keys[1]..':'..time)

    -- Update the receiver records
    redis.call('HINCRBY', 'DID:'..args[4], 'QUEUE_BYTES', bytes)
    redis.call('HINCRBY', 'DID:'..args[4], 'QUEUE_COUNT', 1)
    local RQ = redis.call('XADD', 'RECEIVE_Q:'..args[4], time..'-*', 'MSG_ID', keys[1], 'BYTES', bytes, 'FROM', args[5])
    
    -- Update the sender records
    local SQ = nil
    if table.getn(args) == 6 then
        -- Update the sender records
        redis.call('HINCRBY', 'DID:'..args[6], 'QUEUE_BYTES', bytes)
        redis.call('HINCRBY', 'DID:'..args[6], 'QUEUE_COUNT', 1)
        SQ = redis.call('XADD', 'SEND_Q:'..args[6], time..'-*', 'MSG_ID', keys[1], 'BYTES', bytes, 'TO', args[3])
    end

    -- Update message MetaData
    redis.call('HMSET', 'MSG:META:'..keys[1], 'BYTES', bytes, 'TO', args[4], 'TIMESTAMP', time, 'RECEIVE_ID', RQ)
    if SQ ~= nil then
        redis.call('HMSET', 'MSG:META:'..keys[1], 'FROM', args[6], 'SEND_ID', SQ)
    end

    return redis.status_reply('OK')
end

redis.register_function('store_message', store_message)