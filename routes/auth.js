const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Employee = require('../models/Employee');
const Otp = require('../models/Otp');
const { sendEmail } = require('../utils/sendEmail');

router.post('/login', async (req, res) => {
  const { email, password, otp } = req.body;
  try {
    const employee = await Employee.findOne({ email });
    if (!employee) return res.status(400).json({ message: 'Invalid credentials' });

    if (employee.role === 'admin') {
      if (!password) return res.status(400).json({ message: 'Password required for admin' });
      const isMatch = await bcrypt.compare(password, employee.password);
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
      const token = jwt.sign({ id: employee._id, role: employee.role }, process.env.JWT_SECRET, {
        expiresIn: '1h',
      });
      return res.json({ token, role: employee.role });
    } else {
      if (!otp) {
        const generatedOtp = Math.floor(1000 + Math.random() * 9000).toString();
        await Otp.create({ email, otp: generatedOtp });

        // Professional HTML Email
        const htmlMessage = `
          <div style="font-family: Arial, sans-serif; padding: 15px; color: #333;">
            <h2 style="color:#2E86C1;">Fintradify Login Verification</h2>
            <p>Dear User,</p>
            <p>Your One-Time Password (OTP) for login verification is:</p>
            <h2 style="color:#D35400; letter-spacing:2px;">${generatedOtp}</h2>
            <p>This OTP is valid for <b>10 minutes</b>. Please do not share it with anyone.</p>
            <hr/>
            <p style="font-size:12px; color:#555;">This is an automated message, please do not reply.</p>
            <p><b>Team Fintradify</b></p>
          </div>
        `;

        // Send Email with HTML
        await sendEmail(email, 'Fintradify OTP Verification', htmlMessage, true);

        return res.json({ message: 'OTP sent to email' });
      } else {
        const otpRecord = await Otp.findOne({ email, otp });
        if (!otpRecord) return res.status(400).json({ message: 'Invalid OTP' });
        await Otp.deleteOne({ email, otp });
        const token = jwt.sign({ id: employee._id, role: employee.role }, process.env.JWT_SECRET, {
          expiresIn: '1h',
        });
        return res.json({ token, role: employee.role });
      }
    }
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
