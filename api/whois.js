import { WhoisJson } from '@whoisjson/whoisjson';

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { domain, accessKey } = req.body;

    // Check access key
    const validAccessKey = process.env.ACCESS_KEY;
    
    if (!validAccessKey) {
      return res.status(500).json({ 
        error: 'Server configuration error',
        message: 'ACCESS_KEY not configured'
      });
    }

    if (!accessKey || accessKey !== validAccessKey) {
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'Invalid access key'
      });
    }

    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Clean the domain
    let cleanDomain = domain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .replace(/\/.*$/, '')
      .replace(/:\d+$/, '');

    // Validate domain format
    const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/;
    if (!domainRegex.test(cleanDomain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }

    // Initialize WhoisJson client
    const apiKey = process.env.WHOISJSON_API_KEY;
    
    if (!apiKey) {
      return res.status(500).json({ 
        error: 'API key not configured',
        message: 'Please set WHOISJSON_API_KEY environment variable in Vercel'
      });
    }

    const whois = new WhoisJson({ apiKey });

    // Fetch WHOIS data
    const whoisInfo = await whois.lookup(cleanDomain);

    // Optionally fetch DNS and SSL info
    let dnsInfo = null;
    let sslInfo = null;

    try {
      dnsInfo = await whois.nslookup(cleanDomain);
    } catch (err) {
      console.log('DNS lookup failed:', err.message);
    }

    try {
      sslInfo = await whois.ssl(cleanDomain);
    } catch (err) {
      console.log('SSL lookup failed:', err.message);
    }

    return res.status(200).json({
      success: true,
      domain: cleanDomain,
      whois: whoisInfo,
      dns: dnsInfo,
      ssl: sslInfo
    });

  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ 
      error: 'Failed to fetch WHOIS information',
      message: error.message 
    });
  }
}