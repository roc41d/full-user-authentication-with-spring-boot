package com.sentinelql.authentication.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring5.SpringTemplateEngine;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Async
    public void sendEmail(
            String to,
            String username,
            String templateName,
            String confirmationUrl
    ) throws MessagingException {
        if (!StringUtils.hasLength(templateName)) {
            templateName = "confirm-email";
        }

        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper messageHelper = new MimeMessageHelper(
                mimeMessage,
                MimeMessageHelper.MULTIPART_MODE_MIXED,
                StandardCharsets.UTF_8.name()
                );
        Map<String, Object> mailProperties = new HashMap<>();
        mailProperties.put("username", username);
        mailProperties.put("confirmationUrl", confirmationUrl);

        Context context = new Context();
        context.setVariables(mailProperties);

        messageHelper.setFrom("test@sentinelql.com");
        messageHelper.setTo(to);
        messageHelper.setSubject("Confirm your email");

        String template = templateEngine.process(templateName, context);

        messageHelper.setText(template, true);

        mailSender.send(mimeMessage);
    }
}
