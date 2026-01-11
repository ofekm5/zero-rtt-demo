# Testing Strategy

### Unit Testing
- Flow table operations (create, update, lookup)
- Sequence number rewriting algorithms
- Packet checksum recalculation
- TCP flag detection and handling

### Integration Testing
- End-to-end connection establishment
- Data transmission correctness
- Multiple concurrent connections
- Connection teardown (FIN/RST handling)

### Performance Testing
- Measure time-to-first-byte with and without 0-RTT
- Latency impact of packet rewriting
- Throughput comparison
- Concurrent connection scaling

### Demonstration Scenarios
1. **HTTP Request**: Show 0-RTT benefit for simple GET request
2. **Repeated Connections**: Demonstrate benefit for connection-heavy workloads
3. **High-Latency Network**: Simulate satellite/intercontinental links (100-500ms RTT)