package it.smartcommunitylab.aac.otp.persistance;


import it.smartcommunitylab.aac.repository.CustomJpaRepository;
import it.smartcommunitylab.aac.repository.DetachableJpaRepository;

import java.util.List;

public interface InternalUserOTPRepository extends CustomJpaRepository<InternalUserOTPEntity, String>, DetachableJpaRepository<InternalUserOTPEntity> {
    
    List<InternalUserOTPEntity> findByRepositoryId(String repositoryId);

    List<InternalUserOTPEntity> findByRealm(String realm);

    List<InternalUserOTPEntity> findByRepositoryIdAndUserId(String repositoryId, String userId);

    InternalUserOTPEntity findByRepositoryIdAndUserIdAndStatusOrderByCreateDateDesc(
        String repositoryId,
        String userId,
        String status
    );

    InternalUserOTPEntity findByRepositoryIdAndResetKey(String repositoryId, String key);
    
}