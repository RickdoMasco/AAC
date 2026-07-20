package it.smartcommunitylab.aac.otp.persistance;

import java.util.List;

import it.smartcommunitylab.aac.repository.CustomJpaRepository;
import it.smartcommunitylab.aac.repository.DetachableJpaRepository;

public interface InternalUserOtpEntityRepository
        extends CustomJpaRepository<InternalUserOtpEntity, String>, DetachableJpaRepository<InternalUserOtpEntity> {

    List<InternalUserOtpEntity> findByRepositoryId(String repositoryId);

    List<InternalUserOtpEntity> findByRealm(String realm);

    List<InternalUserOtpEntity> findByRepositoryIdAndUserId(String repositoryId, String userId);

    InternalUserOtpEntity findByRepositoryIdAndUserIdAndStatusOrderByCreateDateDesc(
            String repositoryId,
            String userId,
            String status);

    List<InternalUserOtpEntity> findByRepositoryIdAndConsumed(String repositoryId, boolean consumed);

    List<InternalUserOtpEntity> findByToken(String token);

    List<InternalUserOtpEntity> findByConsumed(boolean consumed);

    List<InternalUserOtpEntity> findByAttemptsGreaterThanEqual(int attempts);

    List<InternalUserOtpEntity> findByExpiryTimestampLessThan(long timestamp);

}
