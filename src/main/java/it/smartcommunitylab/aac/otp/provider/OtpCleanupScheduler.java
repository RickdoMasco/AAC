package it.smartcommunitylab.aac.otp.provider;

import java.util.List;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import it.smartcommunitylab.aac.otp.persistance.InternalUserOtpEntity;
import it.smartcommunitylab.aac.otp.persistance.InternalUserOtpEntityRepository;

@Component
public class OtpCleanupScheduler {
    private final InternalUserOtpEntityRepository repository;

    public OtpCleanupScheduler(InternalUserOtpEntityRepository repository) {
        this.repository = repository;
    }

    @Scheduled(cron = "0 0 4 * * *")
    @Transactional
    public void cleanup() {
        // Rimuovi solo scaduti da almeno 1 ora (buffer sicurezza)
        long buffer = System.currentTimeMillis() - 3600000;
        
        List<InternalUserOtpEntity> expired = repository.findByExpiryTimestampLessThan(buffer);
        repository.deleteAll(expired);
        
        // Rimuovi consumati o troppi tentativi (inutili)
        List<InternalUserOtpEntity> consumed = repository.findByConsumed(true);
        repository.deleteAll(consumed);
        
        List<InternalUserOtpEntity> highAttempts = repository.findByAttemptsGreaterThanEqual(3);
        repository.deleteAll(highAttempts);
    }
}