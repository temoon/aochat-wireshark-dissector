#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include <epan/packet.h>


#define AO_PORT_TEST 7109
#define AO_PORT_RK1 7101
#define AO_PORT_RK2 7102

#define AO_TYPE_BYTE 1
#define AO_TYPE_INT 2
#define AO_TYPE_STR 3
#define AO_TYPE_CHANNEL_ID 4
#define AO_TYPE_INT_TUPLE 5
#define AO_TYPE_STR_TUPLE 6

#define AO_PACKET_SEED 0
#define AO_PACKET_AUTH 2
#define AO_PACKET_LOGIN 3
#define AO_PACKET_OK 5
#define AO_PACKET_ERROR 6
#define AO_PACKET_CHARACTERS_LIST 7
#define AO_PACKET_CHARACTER_UNKNOWN 10
#define AO_PACKET_CHARACTER_UPDATE 20
#define AO_PACKET_CHARACTER_LOOKUP 21
#define AO_PACKET_PRIVATE_MESSAGE 30
#define AO_PACKET_VICINITY_MESSAGE 34
#define AO_PACKET_BROADCAST_MESSAGE 35
#define AO_PACKET_SYSTEM_MESSAGE 36
#define AO_PACKET_CHAT_NOTICE 37
#define AO_PACKET_FRIEND_UPDATE 40
#define AO_PACKET_FRIEND_REMOVE 41
#define AO_PACKET_PRIVATE_CHANNEL_INVITE 50
#define AO_PACKET_PRIVATE_CHANNEL_KICK 51
#define AO_PACKET_PRIVATE_CHANNEL_JOIN 52
#define AO_PACKET_PRIVATE_CHANNEL_LEAVE 53
#define AO_PACKET_PRIVATE_CHANNEL_KICK_ALL 54
#define AO_PACKET_PRIVATE_CHANNEL_CHARACTER_JOIN 55
#define AO_PACKET_PRIVATE_CHANNEL_CHARACTER_LEAVE 56
#define AO_PACKET_PRIVATE_CHANNEL_MESSAGE 57
#define AO_PACKET_PRIVATE_CHANNEL_INVITE_REFUSE 58
#define AO_PACKET_CHANNEL_JOIN 60
#define AO_PACKET_CHANNEL_LEAVE 61
#define AO_PACKET_CHANNEL_MESSAGE 65
#define AO_PACKET_PING 100
#define AO_PACKET_CHAT_COMMAND 120


static int proto_aochat = -1;

static gint ett_aochat = -1;
static gint ett_aochat_data = -1;
static gint ett_aochat_data_tuple = -1;

static int hf_aochat_head_type = -1;
static int hf_aochat_head_length = -1;
static int hf_aochat_data = -1;
static int hf_aochat_data_unknown = -1;
static int hf_aochat_data_byte = -1;
static int hf_aochat_data_int = -1;
static int hf_aochat_data_str= -1;
static int hf_aochat_data_channel_id = -1;
static int hf_aochat_data_tuple = -1;


typedef struct packet {
    const guint16 type;
    const char server_types[4];
    const char client_types[4];
} packet_t;


static const value_string packet_types[] = {
    { AO_PACKET_SEED, "Seed" },
    { AO_PACKET_AUTH, "Authorization" },
    { AO_PACKET_LOGIN, "Login" },
    { AO_PACKET_OK, "OK" },
    { AO_PACKET_ERROR, "Error" },
    { AO_PACKET_CHARACTERS_LIST, "Characters List" },
    { AO_PACKET_CHARACTER_UNKNOWN, "Unknown Character" },
    { AO_PACKET_CHARACTER_UPDATE, "Character Update" },
    { AO_PACKET_CHARACTER_LOOKUP, "Character Lookup" },
    { AO_PACKET_PRIVATE_MESSAGE, "Private Message" },
    { AO_PACKET_VICINITY_MESSAGE, "Vicinity Message" },
    { AO_PACKET_BROADCAST_MESSAGE, "Broadcast Message" },
    { AO_PACKET_SYSTEM_MESSAGE, "System Message" },
    { AO_PACKET_CHAT_NOTICE, "Chat Notice" },
    { AO_PACKET_FRIEND_UPDATE, "Friend Update" },
    { AO_PACKET_FRIEND_REMOVE, "Friend Remove" },
    { AO_PACKET_PRIVATE_CHANNEL_INVITE, "Private Channel Invite" },
    { AO_PACKET_PRIVATE_CHANNEL_KICK, "Private Channel Kick" },
    { AO_PACKET_PRIVATE_CHANNEL_JOIN, "Private Channel Join" },
    { AO_PACKET_PRIVATE_CHANNEL_LEAVE, "Private Channel Leave" },
    { AO_PACKET_PRIVATE_CHANNEL_KICK_ALL, "Private Channel Kick All" },
    { AO_PACKET_PRIVATE_CHANNEL_CHARACTER_JOIN, "Private Channel Character Join" },
    { AO_PACKET_PRIVATE_CHANNEL_CHARACTER_LEAVE, "Private Channel Character Leave" },
    { AO_PACKET_PRIVATE_CHANNEL_MESSAGE, "Private Channel Message" },
    { AO_PACKET_PRIVATE_CHANNEL_INVITE_REFUSE, "Private Channel Invite Refuse" },
    { AO_PACKET_CHANNEL_JOIN, "Channel Join" },
    { AO_PACKET_CHANNEL_LEAVE, "Channel Leave" },
    { AO_PACKET_CHANNEL_MESSAGE, "Channel Message" },
    { AO_PACKET_PING, "Ping" },
    { AO_PACKET_CHAT_COMMAND, "Chat Command" }
};


static const packet_t packets[] = {
    {
        AO_PACKET_SEED,
        { AO_TYPE_STR },
        { AO_TYPE_INT, AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_STR },
    },
    
    {
        AO_PACKET_AUTH,
        { AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_STR },
        { AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_STR },
    },
    
    {
        AO_PACKET_LOGIN,
        { AO_TYPE_INT },
        { AO_TYPE_INT },
    },
    
    {
        AO_PACKET_OK,
        { },
        { },
    },
    
    {
        AO_PACKET_ERROR,
        { AO_TYPE_STR },
        { AO_TYPE_STR },
    },
    
    {
        AO_PACKET_CHARACTERS_LIST,
        { AO_TYPE_INT_TUPLE, AO_TYPE_STR_TUPLE, AO_TYPE_INT_TUPLE, AO_TYPE_INT_TUPLE },
        { AO_TYPE_INT_TUPLE, AO_TYPE_STR_TUPLE, AO_TYPE_INT_TUPLE, AO_TYPE_INT_TUPLE },
    },
    
    {
        AO_PACKET_CHARACTER_UNKNOWN,
        { AO_TYPE_INT },
        { AO_TYPE_INT },
    },
    
    {
        AO_PACKET_CHARACTER_UPDATE,
        { AO_TYPE_INT, AO_TYPE_STR },
        { AO_TYPE_INT, AO_TYPE_STR },
    },
    
    {
        AO_PACKET_CHARACTER_LOOKUP,
        { AO_TYPE_INT, AO_TYPE_STR },
        { AO_TYPE_STR },
    },
    
    {
        AO_PACKET_PRIVATE_MESSAGE,
        { AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_BYTE },
        { AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_BYTE },
    },
    
    {
        AO_PACKET_VICINITY_MESSAGE,
        { AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_BYTE },
        { AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_BYTE },
    },
    
    {
        AO_PACKET_BROADCAST_MESSAGE,
        { AO_TYPE_STR, AO_TYPE_STR, AO_TYPE_STR },
        { AO_TYPE_STR, AO_TYPE_STR, AO_TYPE_STR },
    },
    
    {
        AO_PACKET_SYSTEM_MESSAGE,
        { AO_TYPE_STR },
        { AO_TYPE_STR },
    },
    
    {
        AO_PACKET_CHAT_NOTICE,
        { AO_TYPE_INT, AO_TYPE_INT, AO_TYPE_INT, AO_TYPE_STR },
        { AO_TYPE_INT, AO_TYPE_INT, AO_TYPE_INT, AO_TYPE_STR },
    },
    
    {
        AO_PACKET_FRIEND_UPDATE,
        { AO_TYPE_INT, AO_TYPE_INT, AO_TYPE_BYTE },
        { AO_TYPE_INT, AO_TYPE_BYTE },
    },
    
    {
        AO_PACKET_FRIEND_REMOVE,
        { AO_TYPE_INT },
        { AO_TYPE_INT },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_INVITE,
        { AO_TYPE_INT },
        { AO_TYPE_INT },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_KICK,
        { AO_TYPE_INT },
        { AO_TYPE_INT },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_JOIN,
        { AO_TYPE_INT },
        { AO_TYPE_INT },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_LEAVE,
        { AO_TYPE_INT },
        { AO_TYPE_INT },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_KICK_ALL,
        { },
        { },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_CHARACTER_JOIN,
        { AO_TYPE_INT, AO_TYPE_INT },
        { AO_TYPE_INT, AO_TYPE_INT },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_CHARACTER_LEAVE,
        { AO_TYPE_INT, AO_TYPE_INT },
        { AO_TYPE_INT, AO_TYPE_INT },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_MESSAGE,
        { AO_TYPE_INT, AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_STR },
        { AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_STR },
    },
    
    {
        AO_PACKET_PRIVATE_CHANNEL_INVITE_REFUSE,
        { AO_TYPE_INT },
        { AO_TYPE_INT },
    },
    
    {
        AO_PACKET_CHANNEL_JOIN,
        { AO_TYPE_CHANNEL_ID, AO_TYPE_STR, AO_TYPE_INT, AO_TYPE_STR },
        { AO_TYPE_CHANNEL_ID, AO_TYPE_STR, AO_TYPE_INT, AO_TYPE_STR },
    },
    
    {
        AO_PACKET_CHANNEL_LEAVE,
        { AO_TYPE_CHANNEL_ID },
        { AO_TYPE_CHANNEL_ID },
    },
    
    {
        AO_PACKET_CHANNEL_MESSAGE,
        { AO_TYPE_CHANNEL_ID, AO_TYPE_INT, AO_TYPE_STR, AO_TYPE_STR },
        { AO_TYPE_CHANNEL_ID, AO_TYPE_STR, AO_TYPE_STR },
    },
    
    {
        AO_PACKET_PING,
        { AO_TYPE_BYTE },
        { AO_TYPE_BYTE },
    },
    
    {
        AO_PACKET_CHAT_COMMAND,
        { AO_TYPE_STR_TUPLE, AO_TYPE_INT },
        { AO_TYPE_STR_TUPLE, AO_TYPE_INT },
    },
};


static void tree_add_item(char type, guint *offset, proto_tree *tree, tvbuff_t *tvb) {
    guint16 len = 0;
    
    char tuple_type = 0;
    
    proto_item *tuple_item = NULL;
    proto_tree *tuple_tree = NULL;
    
    switch (type) {
        case AO_TYPE_BYTE:
            len = tvb_get_ntohs(tvb, *offset); *offset += 2;
            proto_tree_add_item(tree, hf_aochat_data_byte, tvb, *offset, len, FALSE); *offset += len;
            break;
        
        case AO_TYPE_INT:
            proto_tree_add_item(tree, hf_aochat_data_int, tvb, *offset, 4, FALSE); *offset += 4;
            break;
        
        case AO_TYPE_STR:
            len = tvb_get_ntohs(tvb, *offset); *offset += 2;
            proto_tree_add_item(tree, hf_aochat_data_str, tvb, *offset, len, FALSE); *offset += len;
            break;
        
        case AO_TYPE_CHANNEL_ID:
            proto_tree_add_item(tree, hf_aochat_data_channel_id, tvb, *offset, 5, FALSE); *offset += 5;
            break;
        
        case AO_TYPE_INT_TUPLE:
        case AO_TYPE_STR_TUPLE:
            len = tvb_get_ntohs(tvb, *offset);
            
            tuple_item = proto_tree_add_item(tree, hf_aochat_data_tuple, tvb, *offset, 2 + len * 2, FALSE); *offset += 2;
            tuple_tree = proto_item_add_subtree(tuple_item, ett_aochat_data_tuple);
            
            if (type == AO_TYPE_INT_TUPLE) {
                tuple_type = AO_TYPE_INT;
            } else if (type == AO_TYPE_STR_TUPLE) {
                tuple_type = AO_TYPE_STR;
            }
            
            while (len--) {
                tree_add_item(tuple_type, offset, tuple_tree, tvb);
            }
            
            break;
    }
}


char check_direction(guint16 packet_length, const char *types, guint *offset, tvbuff_t *tvb) {
    guint16 len = 0;
    
    unsigned char i = 0;
    
    for (i = 0; i < sizeof(types) / sizeof(char); i++) {
        switch (types[i]) {
            case AO_TYPE_BYTE:
            case AO_TYPE_STR:
                if (packet_length >= len + 2) {
                    len += 2 + tvb_get_ntohs(tvb, *offset + len);
                    
                    if (packet_length < len) {
                        return 0;
                    }
                } else {
                    return 0;
                }
                
                break;
            
            case AO_TYPE_INT:
                if (packet_length >= len + 4) {
                    len += 4;
                } else {
                    return 0;
                }
                
                break;
            
            case AO_TYPE_CHANNEL_ID:
                if (packet_length >= len + 5) {
                    len += 5;
                } else {
                    return 0;
                }
                
                break;
            
            case AO_TYPE_INT_TUPLE:
                if (packet_length >= len + 2) {
                    len += 2 + tvb_get_ntohs(tvb, *offset + len) * 4;
                    
                    if (packet_length < len) {
                        return 0;
                    }
                } else {
                    return 0;
                }
                
                break;
            
            case AO_TYPE_STR_TUPLE:
                if (packet_length >= len + 2) {
                    guint16 count = tvb_get_ntohs(tvb, *offset + len);
                    len += 2;
                    
                    while (count--) {
                        if (packet_length >= len + 2) {
                            len += 2 + tvb_get_ntohs(tvb, *offset + len);
                            
                            if (packet_length < len) {
                                return 0;
                            }
                        } else {
                            return 0;
                        }
                    }
                    
                    if (packet_length < len) {
                        return 0;
                    }
                } else {
                    return 0;
                }
                
                break;
        }
    }
    
    return (len == packet_length) ? 1 : 0;
}


char tree_make(guint16 packet_type, guint16 packet_length, guint *offset, proto_tree *tree, tvbuff_t *tvb) {
    const packet_t *p = NULL;
    const char *types = NULL;
    
    unsigned char i = 0;
    
    for (i = 0; i < sizeof(packets) / sizeof(packet_t); i++) {
        if (packets[i].type == packet_type) {
            p = &packets[i];
            break;
        }
    }
    
    if (p != NULL && check_direction(packet_length, p->server_types, offset, tvb)) {
        types = p->server_types;
    } else if ( p != NULL && check_direction(packet_length, p->client_types, offset, tvb)) {
        types = p->client_types;
    } else {
        return 0;
    }
    
    for (i = 0; i < sizeof(types) / sizeof(char); i++) {
        tree_add_item(types[i], offset, tree, tvb);
    }
    
    return 1;
}


static void dissect_aochat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AO Chat");
    
    if (tree) {
        guint offset = 0;
        
        while (offset < tvb_reported_length(tvb)) {
            guint16 packet_type   = tvb_get_ntohs(tvb, offset);
            guint16 packet_length = tvb_get_ntohs(tvb, offset + 2);
            
            proto_item *aochat_item      = NULL;
            proto_tree *aochat_tree      = NULL;
            proto_item *aochat_data_item = NULL;
            proto_tree *aochat_data_tree = NULL;
            
            if (offset == 0) {
                col_add_str(pinfo->cinfo, COL_INFO, val_to_str(packet_type, packet_types, "Unknown (%d)"));
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(packet_type, packet_types, "Unknown (%d)"));
            }
            
            aochat_item = proto_tree_add_item(tree, proto_aochat, tvb, offset, 4 + packet_length, FALSE);
            aochat_tree = proto_item_add_subtree(aochat_item, ett_aochat);
            
            proto_item_append_text(aochat_item, ", %s", val_to_str(packet_type, packet_types, "Unknown (%d)"));
            
            proto_tree_add_item(aochat_tree, hf_aochat_head_type,   tvb, offset, 2, FALSE); offset += 2;
            proto_tree_add_item(aochat_tree, hf_aochat_head_length, tvb, offset, 2, FALSE); offset += 2;
            
            if (packet_length) {
                aochat_data_item = proto_tree_add_item(aochat_tree, hf_aochat_data, tvb, offset, packet_length, FALSE);
                aochat_data_tree = proto_item_add_subtree(aochat_data_item, ett_aochat_data);
                
                if (!tree_make(packet_type, packet_length, &offset, aochat_data_tree, tvb)) {
                    proto_tree_add_item(aochat_data_tree, hf_aochat_data_unknown, tvb, offset, packet_length, FALSE); offset += packet_length;
                }
            }
        }
    }
}


void proto_register_aochat(void) {
    static hf_register_info hf[] = {
        { &hf_aochat_head_type,       { "Type",       "aochat.type",            FT_UINT16, BASE_DEC,  VALS(packet_types), 0x0, NULL, HFILL } },
        { &hf_aochat_head_length,     { "Length",     "aochat.length",          FT_UINT16, BASE_DEC,  NULL,               0x0, NULL, HFILL } },
        { &hf_aochat_data,            { "Data",       "aochat.data",            FT_BYTES,  BASE_NONE, NULL,               0x0, NULL, HFILL } },
        { &hf_aochat_data_unknown,    { "Unknown",    "aochat.data.unknown",    FT_BYTES,  BASE_NONE, NULL,               0x0, NULL, HFILL } },
        { &hf_aochat_data_byte,       { "Byte",       "aochat.data.byte",       FT_UINT8,  BASE_DEC,  NULL,               0x0, NULL, HFILL } },
        { &hf_aochat_data_int,        { "Integer",    "aochat.data.int",        FT_UINT32, BASE_DEC,  NULL,               0x0, NULL, HFILL } },
        { &hf_aochat_data_str,        { "String",     "aochat.data.string",     FT_STRING, BASE_NONE, NULL,               0x0, NULL, HFILL } },
        { &hf_aochat_data_channel_id, { "Channel ID", "aochat.data.channel_id", FT_UINT64, BASE_DEC,  NULL,               0x0, NULL, HFILL } },
        { &hf_aochat_data_tuple,      { "Tuple",      "aochat.data.tuple",      FT_BYTES,  BASE_NONE, NULL,               0x0, NULL, HFILL } },
    };
    
    static gint *ett[] = {
        &ett_aochat,
        &ett_aochat_data,
        &ett_aochat_data_tuple,
    };
    
    proto_aochat = proto_register_protocol(
        "Anarchy Online Chat Protocol",
        "AO Chat",
        "aochat"
    );
    
    proto_register_field_array(proto_aochat, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_aochat(void) {
    static dissector_handle_t aochat_handle;
    
    aochat_handle = create_dissector_handle(dissect_aochat, proto_aochat);
    
    dissector_add("tcp.port", AO_PORT_TEST, aochat_handle);
    dissector_add("tcp.port", AO_PORT_RK1, aochat_handle);
    dissector_add("tcp.port", AO_PORT_RK2, aochat_handle);
}
