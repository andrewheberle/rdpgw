package protocol

import "github.com/prometheus/client_golang/prometheus"

var (
	connectionCache = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "connection_cache",
			Help:      "The amount of connections in the cache",
		})

	websocketConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "websocket_connections",
			Help:      "The count of websocket connections",
		})

	websocketConnectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rdpgw",
		Name:      "websocket_connections_total",
		Help:      "The total number of websocket connections handled",
	})

	legacyConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "rdpgw",
			Name:      "legacy_connections",
			Help:      "The count of legacy https connections",
		})

	legacyConnectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rdpgw",
		Name:      "legacy_connections_total",
		Help:      "The total number of legacy https connections handled",
	})

	tunnelPacketsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rdpgw",
		Name:      "tunnel_sent_packets_total",
		Help:      "The total number of packets sent by the server to the client",
	})

	tunnelBytesSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rdpgw",
		Name:      "tunnel_sent_bytes_total",
		Help:      "The total number of bytes sent by the server to the client minus tunnel overhead",
	})

	tunnelPacketsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rdpgw",
		Name:      "tunnel_received_packets_total",
		Help:      "The total number of packets received by the server from the client",
	})

	tunnelBytesReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "rdpgw",
		Name:      "tunnel_received_bytes_total",
		Help:      "The total number of bytes received by the server from the client minus tunnel overhad",
	})

	tunnelSendLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "rdpgw",
		Name:      "tunnel_send_latency",
		Help:      "The observed latency to send traffic from server to client over the tunnel",
	})

	tunnelReceiveLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "rdpgw",
		Name:      "tunnel_receive_latency",
		Help:      "The observed latency to receive traffic from client to the server over the tunnel",
	})
)

func init() {
	prometheus.MustRegister(connectionCache)
	prometheus.MustRegister(legacyConnections)
	prometheus.MustRegister(legacyConnectionsTotal)
	prometheus.MustRegister(websocketConnections)
	prometheus.MustRegister(websocketConnectionsTotal)
	prometheus.MustRegister(tunnelBytesSent)
	prometheus.MustRegister(tunnelBytesReceived)
	prometheus.MustRegister(tunnelPacketsSent)
	prometheus.MustRegister(tunnelPacketsReceived)
	prometheus.MustRegister(tunnelSendLatency)
	prometheus.MustRegister(tunnelReceiveLatency)
}
