#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

#define AO_PORT_TEST 7109
#define AO_PORT_RK1 7101
#define AO_PORT_RK2 7102

#define AO_TYPE_INT 0
#define AO_TYPE_STR 1
#define AO_TYPE_CHANNEL_ID 2
#define AO_TYPE_INT_TUPLE 3
#define AO_TYPE_STR_TUPLE 4

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
static int hf_aochat_data_int = -1;
static int hf_aochat_data_str= -1;
static int hf_aochat_data_channel_id = -1;
static int hf_aochat_data_tuple = -1;

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

static void tree_add_item(gint type, gint *offset, proto_tree *tree, tvbuff_t *tvb) {
    guint16 len = 0;
    
    char tuple_type = 0;
    
    proto_item *tuple_item = NULL;
    proto_tree *tuple_tree = NULL;
    
    switch (type) {
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

static void dissect_aochat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AO Chat");
    
    if (tree) {
        guint16 offset = 0;
        
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
                gint16 len1 = -1;
                gint16 len2 = -1;
                
                aochat_data_item = proto_tree_add_item(aochat_tree, hf_aochat_data, tvb, offset, packet_length, FALSE);
                aochat_data_tree = proto_item_add_subtree(aochat_data_item, ett_aochat_data);
                
                switch (packet_type) {
                    case AO_PACKET_SEED:
                        if (packet_length >= 10) {
                            len1 = tvb_get_ntohs(tvb, offset + 8);
                        } else {
                            len1 = -1;
                        }
                        
                        if (len1 >= 0 && packet_length >= 12 + len1) {
                            len2 = tvb_get_ntohs(tvb, offset + 10 + len1);
                        } else {
                            len2 = -1;
                        }
                        
                        // From client
                        if (len1 >= 0 && len2 >= 0 && packet_length == 12 + len1 + len2) {
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        // From server
                        } else {
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        }
                        
                        break;
                    
                    case AO_PACKET_AUTH:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_LOGIN:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_OK:
                        break;
                    
                    case AO_PACKET_ERROR:
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHARACTERS_LIST:
                        tree_add_item(AO_TYPE_INT_TUPLE, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR_TUPLE, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT_TUPLE, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT_TUPLE, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHARACTER_UNKNOWN:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHARACTER_UPDATE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHARACTER_LOOKUP:
                        if (packet_length >= 6) {
                            len1 = tvb_get_ntohs(tvb, offset + 4);
                        } else {
                            len1 = -1;
                        }
                        
                        // From server
                        if (len1 >= 0 && packet_length == 6 + len1) {
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        } else {
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        }
                        
                        break;
                    
                    case AO_PACKET_PRIVATE_MESSAGE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_VICINITY_MESSAGE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_BROADCAST_MESSAGE:
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_SYSTEM_MESSAGE:
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHAT_NOTICE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_FRIEND_UPDATE:
                        if (packet_length >= 10) {
                            len1 = tvb_get_ntohs(tvb, offset + 8);
                        } else {
                            len1 = -1;
                        }
                        
                        // From server
                        if (len1 >= 0 && packet_length == 10 + len1) {
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        // From client
                        } else {
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        }
                        
                        break;
                    
                    case AO_PACKET_FRIEND_REMOVE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_PRIVATE_CHANNEL_INVITE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        break;
                    case AO_PACKET_PRIVATE_CHANNEL_KICK:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_PRIVATE_CHANNEL_JOIN:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_PRIVATE_CHANNEL_LEAVE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_PRIVATE_CHANNEL_KICK_ALL:
                        break;
                    
                    case AO_PACKET_PRIVATE_CHANNEL_CHARACTER_JOIN:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_PRIVATE_CHANNEL_CHARACTER_LEAVE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_PRIVATE_CHANNEL_MESSAGE:
                        if (packet_length >= 10) {
                            len1 = tvb_get_ntohs(tvb, offset + 8);
                        } else {
                            len1 = -1;
                        }
                        
                        if (len1 >= 0 && packet_length >= 12 + len1) {
                            len2 = tvb_get_ntohs(tvb, offset + 10 + len1);
                        } else {
                            len2 = -1;
                        }
                        
                        // From server
                        if (len1 >= 0 && len2 >= 0 && packet_length == 12 + len1 + len2) {
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        // From client
                        } else {
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        }
                        
                        break;
                    
                    case AO_PACKET_PRIVATE_CHANNEL_INVITE_REFUSE:
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHANNEL_JOIN:
                        tree_add_item(AO_TYPE_CHANNEL_ID, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHANNEL_LEAVE:
                        tree_add_item(AO_TYPE_CHANNEL_ID, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHANNEL_MESSAGE:
                        if (packet_length >= 11) {
                            len1 = tvb_get_ntohs(tvb, offset + 9);
                        } else {
                            len1 = -1;
                        }
                        
                        if (len1 >= 0 && packet_length >= 13 + len1) {
                            len2 = tvb_get_ntohs(tvb, offset + 11 + len1);
                        } else {
                            len2 = -1;
                        }
                        
                        // From server
                        if (len1 >= 0 && len2 >= 0 && packet_length == 13 + len1 + len2) {
                            tree_add_item(AO_TYPE_CHANNEL_ID, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        // From client
                        } else {
                            tree_add_item(AO_TYPE_CHANNEL_ID, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                            tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        }
                        
                        break;
                    
                    case AO_PACKET_PING:
                        tree_add_item(AO_TYPE_STR, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    case AO_PACKET_CHAT_COMMAND:
                        tree_add_item(AO_TYPE_STR_TUPLE, &offset, aochat_data_tree, tvb);
                        tree_add_item(AO_TYPE_INT, &offset, aochat_data_tree, tvb);
                        
                        break;
                    
                    default:
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
