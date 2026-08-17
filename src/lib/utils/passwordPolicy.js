export const validatePassword = (password) => {
  const requirements = [
    { id: 'length', text: '12 to 72 characters', test: (p) => p.length >= 12 && p.length <= 72 },
    { id: 'uppercase', text: 'At least 1 uppercase letter', test: (p) => /[A-Z]/.test(p) },
    { id: 'lowercase', text: 'At least 1 lowercase letter', test: (p) => /[a-z]/.test(p) },
    { id: 'number', text: 'At least 1 number', test: (p) => /[0-9]/.test(p) },
    { id: 'special', text: 'At least 1 special character', test: (p) => /[^A-Za-z0-9]/.test(p) }
  ];

  const results = requirements.map(req => ({
    ...req,
    met: req.test(password || '')
  }));

  const isValid = results.every(r => r.met);

  return { isValid, results };
};
