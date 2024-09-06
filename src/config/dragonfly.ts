import { createClient } from 'redis';

const dragonflyClient = createClient({
  url: process.env.REDIS_URL
});

dragonflyClient.on('error', (err) => {
  console.error('Redis connection error:', err);
});

dragonflyClient.connect();

export default dragonflyClient;