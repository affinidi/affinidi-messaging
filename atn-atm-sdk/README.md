
# Affinidi Trusted Messaging SDK

## Debug logging

To enable logging at DEBUG level just for atm_sdk crate

`export RUST_LOG=none,atn_atm_sdk=debug`

## Examples

To enable logging for examples, `export RUST_LOG=none,atn_atm_sdk=debug,ping=debug,demo=debug`

* Send a trust ping

    `cargo run --example ping`

* Run the demo

    `cargo run --example demo`

## API Calls

### DIDComm Trust-Ping

* It can be useful to send a Trust-Ping to a target to test connectivity and routing.
* If you have control of the target, then a response may not be needed. Otherwise you can request a response.

***NOTE:*** If you a sending an anonymous message, then there is no ability to get a response.

```rust
async fn send_ping(to_did: &str, signed: bool, response:bool) -> Result<(), ATMError>
// Sends a ping to an address via ATM
// - to_did   : DID to ping
// - signed   : if true, then message is signed with your DID, if false then sent anonymous
// - response : Request a PONG response from the target? If signed == false, then this will also be reset to false

// Example: Send a signed trust-ping requesting a response from the target
send_ping("did:example:target#123", true, true).await?;
```

Response from `send_ping()` is:

* Success : Result->Ok with no object
* Error   : Result->Err with ATMError object describing the error

### List Messages

* ATM supports two message folders:
  * Inbox (incoming messages sent to you)
  * Outbox (outbound messages you have sent that have not been delivered to the next node)
* `enum Folder` holds the folder types

```rust
aync fn list_messages(did: &str, folder: Folder) -> Result<MessageList, ATMError>
// Retrieves a list of messages for the specified DID (you must own this DID)
// - did    : DID that we want to retrieve messages from (must have authenticated as this DID)
// - folder : Folder enum of either Inbox or Outbox

// Example:
list_messages("did:example:target#123", Folder::Inbox).await?;
```

Response from `list_messages()` is:

* Success : Result->Ok `MessageList` struct containing a list of messages including Metadata
* Error   : Result->Err with ATMError object describing the error

### Delete Messages

* Deletes one or more messages from ATM, you need to know the message_ids first!
* Receiver can delete any message that is waiting to be delivered to them
* Sender can delete any message that is waiting still to be delivered for them

```rust
async fn delete_messages(messages: &DeleteMessageRequest) -> Result<DeleteMessageResponse, ATMError>
// Deletes a set of messages contained in an array
// - messages : Vec<String> of message hash ID's

// Example:
delete_messages(&vec!["message_hash1", "message_hash2", ...]).await?;
```

Response from `delete_messages()` is:

* Success : Result->Ok `DeleteMessageResponse` struct
* Error   : Result->Err with ATMError object describing the error

Working with `DeleteMessageResponse`:

* success `Vec<String>`           : List of message_id's that were successfully deleted
* errors  `Vec<(String, String)>` : List of message_id's and error information

### Send DIDComm Message

* Sends a DIDComm packed message to ATM
* Creating the DIDComm message is not handled by this call

```rust
async fn send_didcomm_message<T>(msg: &str) -> Result<SuccessResponse<T>, ATMError>
// Sends a DIDComm packed message to ATM
// Can specify the return type via <T>

// Example:

let msg = msg.pack(to, from, options ...);
send_didcomm_message(&msg).await?;
```

Response from `send_didcomm_message()` is:

* Success : Result->Ok `SuccessResponse<T>` struct (where the data field of `SuccessResponse` is of type `<T>`)
* Error   : Result->Err with ATMError object describing the error

### Get DIDComm Message

* Retrieves one or more messages from ATM
* You must know the message_id(s) in advance. See `list_messages()`
* You can specify if you want to delete along with the get_message() request
* Call `unpack(&message)` next to unpack the message you have received

```rust
async fn get_messages(messages: &GetMessagesRequest) -> Result<GetMessagesResponse, ATMError>
// Gets one or more messages from ATM

// Example: Get one message, and don't delete it
get_messages(&vec!["message_id".into()], false).await?;
```

Response from `get_messages()` is:

* Success : Result->Ok `GetMessagesResponse` struct
* Error   : Result->Err with ATMError object describing the error

Working with `GetMessageResponse`:

* success       `Vec<String>`           : List of message_id's that were successfully deleted
* get_errors    `Vec<(String, String)>` : List of failed gets on message_ids + error message
* delete_errors `vec<(String, String)>` : List of failed deletes on message_ids + error message

### Unpack a DIDComm message

* A wrapper for DIDComm Message::unpack() that simplifies the setup of resolvers etc already done for ATM
* Takes a plain `String` and returns a DIDComm `Message` and `UnpackMetadata` objects

```rust
async fn unpack(message: &str) -> Result<(Message, UnpackMetadata), ATMError>
// Unpacks any DIDComm message into a Message and UnpackMetadata response

// Example:
let didcomm_message = atm.get_messages(&vec!["msg_id".to_string()], true).await?;
let (message, meta_data) = atm.unpack(&didcomm_message).await?;

println!("Message body = {}", message.body);
```

Response from `unpack()` is:

* Success : Result->Ok (`Message`, `UnpackMetadata`)
* Error   : Result->Err with ATMError object describing the error
