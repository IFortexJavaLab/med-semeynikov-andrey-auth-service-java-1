package com.ifortex.internship.authservice.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

  private final JavaMailSender emailSender;

  @Value("${spring.mail.username}")
  private String emailUsername;

  public void sendVerificationEmail(String to, String subject, String otp)
      throws MessagingException {

    log.debug("Sending email with subject '{}' to email: {}", subject, to);
    String htmlMessage =
        "<html>"
            + "<body style=\"font-family: Arial, sans-serif;\">"
            + "<div style=\"background-color: #f5f5f5; padding: 20px;\">"
            + "<h2 style=\"color: #333;\">Welcome to our app!</h2>"
            + "<p style=\"font-size: 16px;\">Please enter the verification code below to continue:</p>"
            + "<div style=\"background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);\">"
            + "<h3 style=\"color: #333;\">Verification Code:</h3>"
            + "<p style=\"font-size: 18px; font-weight: bold; color: #007bff;\">"
            + otp
            + "</p>"
            + "</div>"
            + "</div>"
            + "</body>"
            + "</html>";

    MimeMessage message = emailSender.createMimeMessage();
    MimeMessageHelper helper = new MimeMessageHelper(message, true);

    // feature I am not sure about first line
    helper.setFrom(emailUsername);
    helper.setTo(to);
    helper.setSubject(subject);
    helper.setText(htmlMessage, true);

    emailSender.send(message);

    log.debug("Email with OTP was send to email: {}", to);
  }
}
