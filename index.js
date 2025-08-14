import fetch from "node-fetch";

const URL = "https://team-ghost.onrender.com"; // Your Render URL

async function ping() {
  try {
    const res = await fetch(URL);
    console.log(`[${new Date().toISOString()}] Pinged ${URL} - Status: ${res.status}`);
  } catch (err) {
    console.error(`[${new Date().toISOString()}] Ping failed:`, err.message);
  }

  // Random delay between 20s and 90s
  const delay = Math.floor(Math.random() * (90000 - 20000 + 1)) + 20000;
  setTimeout(ping, delay);
}

// Start the first ping
ping();
