/**
 * Copyright 2014 Unicon (R)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ltistarter.repository;

import ltistarter.model.Lti3KeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional
public interface Lti3KeyRepository extends JpaRepository<Lti3KeyEntity, Long> {

    List<Lti3KeyEntity> findByIss(String iss);

    List<Lti3KeyEntity> findByClientId(String clientId);

    List<Lti3KeyEntity> findByToolKid(String keyId);

    List<Lti3KeyEntity> findByPlatformKid(String keyId);

}
