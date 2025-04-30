from kafka import KafkaProducer
import json

# Initialize the producer
producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# Send a test message to the 'security_logs' topic (which your SIEM expects)
test_message = {
    "event": "ssh_failed",
    "source_ip": "192.168.1.1",
    "count": 6,
    "message": "Bruteforce attempt detected",
    "timestamp": "2023-10-01T12:00:00Z"
}

producer.send('security_logs', value=test_message)
producer.flush()  # Ensure message is sent
print("Test message sent successfully!")
