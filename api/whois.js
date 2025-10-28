module.exports = async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Lazy load the package
    const { WhoisJson } = await import('@whoisjson/whoisjson');
    
    const { domain, accessKey } = req.body;

    console.log('Received request with accessKey:', accessKey ? 'Present' : 'Missing');

    // Check access key
    const validAccessKey = process.env.ACCESS_KEY;
    
    console.log('Environment ACCESS_KEY:', validAccessKey ? 'Set' : 'Not set');
    
    if (!validAccessKey) {
      return res.status(500).json({ 
        error: 'Server configuration error',
        message: 'ACCESS_KEY environment variable is not set'
      });
    }

    if (!accessKey) {
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'No access key provided'
      });
    }

    if (accessKey !== validAccessKey) {
      console.log('Key mismatch - Received:', accessKey, 'Expected:', validAccessKey);
      return res.status(403).json({ 
        error: 'Access denied',
        message: 'Invalid access key'
      });
    }

    console.log('Access key validated successfully');

    if (!domain) {
      return res.status(400).json({ error: 'Domain parameter is required' });
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
      return res.status(400).json({ 
        error: 'Invalid domain format',
        domain: cleanDomain
      });
    }

    // Initialize WhoisJson client
    const apiKey = process.env.WHOISJSON_API_KEY;
    
    if (!apiKey) {
      return res.status(500).json({ 
        error: 'API key not configured',
        message: 'WHOISJSON_API_KEY environment variable is not set in Vercel'
      });
    }

    const whois = new WhoisJson({ apiKey });

    // Fetch WHOIS data
    let whoisInfo = null;
    try {
      whoisInfo = await whois.lookup(cleanDomain);
    } catch (err) {
      return res.status(500).json({
        error: 'WHOIS lookup failed',
        message: err.message,
        domain: cleanDomain
      });
    }

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
    console.error('Unexpected error:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};