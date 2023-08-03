#include "afl_input.h"
#include "input.pb.h"

afl_input::Input g_input;
auto g_packet = g_input.packets().end();

extern "C" void afl_deserialize(uint8_t* buf, uint32_t size) {
    g_input.ParseFromArray(buf, size);
    g_packet = g_input.packets().begin();

    printf("Deserializing %d packets...\n", g_input.packets_size());
    for (const afl_input::Packet& pkt : g_input.packets())
    {
        printf("Packet dump:\n");
        for(int i = 0; i < pkt.buffer().size(); ++i)
        {
            printf("%02X ", pkt.buffer().data()[i]);
            if ((i+1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    }

};

extern "C" int afl_packets_size() {
    return g_input.packets_size();
}

extern "C" void afl_delete_packet(int index) {
    g_input.mutable_packets()->DeleteSubrange(index, 1);
}

extern "C" size_t afl_get_packet(int index, void* buf, size_t size) {
    afl_input::Packet packet = g_input.packets().at(index);
    size_t copy_size = std::min(size, packet.buffer().size());

    memcpy(buf, packet.buffer().data(), copy_size);

    return copy_size;
}

extern "C" void afl_set_packet(int index, void* buf, size_t size) {
    afl_input::Packet packet = g_input.mutable_packets()->at(index);
    packet.ParseFromArray(buf, size);
}

extern "C" size_t afl_serialize(void* buf, size_t size) {
    
    printf("Serializing packets...\n");
    for (auto pkt : g_input.packets())
    {
        printf("Packet dump:\n");
        for(int i = 0; i < pkt.buffer().size(); ++i)
        {
            printf("%02X ", pkt.buffer().data()[i]);
            if ((i+1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    }
    
    g_input.SerializeToArray(buf, size);
    return std::min(size, g_input.ByteSizeLong());
}

extern "C" bool afl_has_next() {
    return g_packet != g_input.packets().end();
}

extern "C" const char* afl_get_next(size_t* out_size) {
    *out_size = g_packet->buffer().size();
    const char* pkt = g_packet->buffer().data();
    g_packet++;
    return pkt;
}