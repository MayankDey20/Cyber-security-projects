// --- COMMON PASSWORDS ARRAY ---
const commonPasswords = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "baseball",
    "iloveyou",
    "football",
    "monkey",
    "letmein",
    "abc123",
    "welcome",
    "login",
    "admin",
    "princess",
    "qwerty123"
  ];
  
  // --- ADVANCED PASSWORD STRENGTH FUNCTION ---
  function advancedPasswordStrength(password) {
    let score = 0;
  
    // Length criteria: 8+ gets 2 points; 12+ gets an extra 2.
    if (password.length >= 8) score += 2;
    if (password.length >= 12) score += 2;
  
    // Character variety criteria.
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
  
    // Deduct points for common sequences or patterns.
    const sequences = [
      "0123", "1234", "2345", "3456", "4567", "5678", "6789",
      "abcd", "bcde", "cdef", "defg", "efgh", "fghi", "ghij"
    ];
    sequences.forEach(seq => {
      if (password.toLowerCase().includes(seq)) {
        score -= 1;
      }
    });
  
    let strengthText = "";
    if (score >= 8) strengthText = `Score: ${score} - Very Strong 💪`;
    else if (score >= 5) strengthText = `Score: ${score} - Strong 😊`;
    else if (score >= 3) strengthText = `Score: ${score} - Moderate 😐`;
    else strengthText = `Score: ${score} - Weak ❌`;
  
    return strengthText;
  }
  
  // --- SHA-1 HASH FUNCTION USING WEB CRYPTO API ---
  async function sha1(str) {
    const buffer = new TextEncoder("utf-8").encode(str);
    const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hashHex;
  }
  
  // --- HAVE I BEEN PWNED API CHECK ---
  async function checkPwned(password) {
    try {
      const hash = await sha1(password);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!response.ok) throw new Error("Error contacting API");
      const data = await response.text();
      const lines = data.split("\n");
      for (let line of lines) {
        let [hashSuffix, count] = line.split(":");
        if (hashSuffix.trim() === suffix) {
          return parseInt(count.trim());
        }
      }
      return 0;
    } catch (error) {
      console.error(error);
      return null;
    }
  }
  
  // --- UPDATE PASSWORD FEEDBACK ON INPUT ---
  async function updatePasswordFeedback() {
    const password = document.getElementById("password").value;
    const feedbackEl = document.getElementById("passwordFeedback");
    let feedback = "";
  
    // Check if password is in the common list (case insensitive).
    if (commonPasswords.includes(password.toLowerCase())) {
      feedback += "<span class='text-red-600 font-bold'>This is a common password. </span><br>";
    }
  
    // Password strength evaluation.
    feedback += advancedPasswordStrength(password) + "<br>";
  
    // Check breach status with Have I Been Pwned.
    const pwnedCount = await checkPwned(password);
    if (pwnedCount === null) {
      feedback += "<span class='text-yellow-600'>Error checking breaches.</span>";
    } else if (pwnedCount > 0) {
      feedback += `<span class='text-red-600 font-bold'>Warning:</span> This password has been seen ${pwnedCount} times in data breaches.`;
    } else {
      feedback += "<span class='text-green-600'>Good news: This password was not found in any data breaches!</span>";
    }
  
    feedbackEl.innerHTML = feedback;
  }
  
  // --- EVENT LISTENERS ---
  document.getElementById("password").addEventListener("input", updatePasswordFeedback);
  
  document.getElementById("loginForm").addEventListener("submit", function (e) {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    alert(`Username: ${username}\nPassword: ${password}\nSee console for password analysis.`);
  });
  