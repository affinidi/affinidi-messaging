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
    local time = redis.call('TIME')
    local time = string.format("%d%.0f", time[1], time[2]/1000)
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
    -- If changing the fields in the future, update the fetch_messages function
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

-- delete_message
-- keys = message_hash
-- args = [1] did_hash
local function delete_message(keys, args)
    -- Correct number of keys?
    if #keys ~= 1  then
        return redis.error_reply('delete_message: only accepts one key')
    end

    -- Correct number of args?
    if #args ~= 1 then
        return redis.error_reply('delete_message: Requires DID hash argument')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Retrieve message metadata
    local meta = redis.call('HGETALL', 'MSG:META:'..keys[1])
    if meta.map == nil then
        return redis.error_reply('Couldn\'t retrieve metadata')
    end

    -- Check that the requesting DID has some form of ownership of this message
    if meta.map.TO ~= args[1] and meta.map.FROM ~= args[1] then
        return redis.error_reply('Requesting DID does not have ownership of this message')
    end

    local bytes = meta.map.BYTES
    if bytes == nil then
        redis.log(redis.LOG_WARNING, 'message ('..keys[1]..') metadata did not contain BYTES field.')
        return redis.error_reply('message ('..keys[1]..') metadata did not contain BYTES field.')
    end
    
    -- Delete message
    redis.call('DEL', 'MSG:'..keys[1])

    -- Set Global Metrics
    redis.call('HINCRBY', 'GLOBAL', 'RECEIVED_BYTES', -bytes)
    redis.call('HINCRBY', 'GLOBAL', 'DELETED_COUNT', 1)

    -- Remove the receiver records
    redis.call('HINCRBY', 'DID:'..meta.map.TO, 'QUEUE_BYTES', -bytes)
    redis.call('HINCRBY', 'DID:'..meta.map.TO, 'QUEUE_COUNT', -1)
    redis.call('XDEL', 'RECEIVE_Q:'..meta.map.TO, meta.map.RECEIVE_ID)
    
    -- Remove the sender records
    local SQ = nil
    if meta.map.SEND_ID ~= nil then
        -- Remove the sender records
        redis.call('HINCRBY', 'DID:'..meta.map.FROM, 'QUEUE_BYTES', -bytes)
        redis.call('HINCRBY', 'DID:'..meta.map.FROM, 'QUEUE_COUNT', -1)
        SQ = redis.call('XDEL', 'SEND_Q:'..meta.map.FROM, meta.map.SEND_ID)
    end

    -- Remove the message metadata
    redis.call('DEL', 'MSG:META:'..keys[1])

    return redis.status_reply('OK')    
end

-- fetch_messages
-- keys = did_hash
-- args = [1] start_id
--        [2] limit
local function fetch_messages(keys, args)
    -- Do we have the correct number of arguments?
    if #args ~= 2  then
        return redis.error_reply('fetch_messages: wrong arguments')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Prepend an exclusive start_id if it exists
    local start_id = '-'
    if args[1] ~= "-" then
        start_id = '('..args[1]
    end

    -- Get list of messages from stream
    local list = redis.call('XRANGE', 'RECEIVE_Q:'..keys[1], start_id, '+', 'COUNT', args[2])

    local fetched_messages = {}
    -- unpack the XRANGE list
    for x, element in ipairs(list) do
        -- element[1] = stream_id
        -- element[2] = array of Stream Fields
        for i, sub_element in ipairs(element) do
            if i == 1 then 
                -- This is the stream ID
                fetched_messages[x] = {'STREAM_ID', sub_element}
            else
                -- [1] = MSG_ID
                -- [2] = message_id
                -- [3] = BYTES
                -- [4] = bytes
                -- [5] = FROM
                -- [6] = from_did
                table.insert(fetched_messages[x], sub_element[1])
                table.insert(fetched_messages[x], sub_element[2])
                table.insert(fetched_messages[x], 'FROM_DID')
                table.insert(fetched_messages[x], sub_element[6])

                -- fetch the message
                table.insert(fetched_messages[x], 'MSG')
                local msg = redis.call('GET', 'MSG:'..sub_element[2])
                table.insert(fetched_messages[x], msg)

                -- fetch the message metadata
                local meta = redis.call('HGETALL', 'MSG:META:'..sub_element[2])
                for k, v in pairs(meta.map) do
                    table.insert(fetched_messages[x], 'META_'..k)
                    table.insert(fetched_messages[x], v)
                end
            end
        end
    end -- end of XRANGE list

    return fetched_messages
end

redis.register_function('store_message', store_message)
redis.register_function('delete_message', delete_message)
redis.register_function('fetch_messages', fetch_messages)