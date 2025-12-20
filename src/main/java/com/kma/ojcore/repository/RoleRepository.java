package com.kma.ojcore.repository;

import com.kma.ojcore.entity.Role;
import com.kma.ojcore.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(RoleName name);

    Boolean existsByName(RoleName name);

    default Role getUserRole() {
        return findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("User Role not found"));
    }
}

