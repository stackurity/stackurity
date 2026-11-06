-- A channel's last real delivery (Channel.LastDeliveryAt, the
-- integration's "last message delivered"), read with every channel list
-- without scanning the delivery log.
CREATE INDEX deliveries_channel_sent ON deliveries (channel_id, sent_at) WHERE status = 'sent';
