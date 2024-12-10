/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.common.logging.Logger;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import org.dependencytrack.event.PolicyEvaluationEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.policy.PolicyEngine;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import static org.dependencytrack.common.MdcKeys.MDC_EVENT_TOKEN;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_NAME;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_UUID;
import static org.dependencytrack.common.MdcKeys.MDC_PROJECT_VERSION;
import static org.dependencytrack.util.LockUtil.getLockForProjectAndNamespace;

public class PolicyEvaluationTask implements Subscriber {
    private static final Logger LOGGER = Logger.getLogger(PolicyEngine.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (!(e instanceof final PolicyEvaluationEvent event)) {
            LOGGER.info("LanceLog Received an unrelated event");
            return;
        }
        if (event.getProject() == null) {
            LOGGER.info("LanceLog Project NULL");
            return;
        }

        final ReentrantLock lock = getLockForProjectAndNamespace(event.getProject(), getClass().getSimpleName());
        try (var ignoredMdcProjectUuid = MDC.putCloseable(MDC_PROJECT_UUID, event.getProject().getUuid().toString());
             var ignoredMdcProjectName = MDC.putCloseable(MDC_PROJECT_NAME, event.getProject().getName());
             var ignoredMdcProjectVersion = MDC.putCloseable(MDC_PROJECT_VERSION, event.getProject().getVersion());
             var ignoredMdcEventToken = MDC.putCloseable(MDC_EVENT_TOKEN, event.getChainIdentifier().toString())) {
            lock.lock();
            if (event.getComponents() != null && !event.getComponents().isEmpty()) {
                performPolicyEvaluation(event.getProject(), event.getComponents());
                LOGGER.info("LanceLog Project performPolicyEvaluation event.getComponents");
            } else {
                performPolicyEvaluation(event.getProject(), new ArrayList<>());
                LOGGER.info("LanceLog Project performPolicyEvaluation new ArrayList");
            }
        } finally {
            lock.unlock();
        }
    }

    private void performPolicyEvaluation(Project project, List<Component> components) {
        final PolicyEngine pe = new PolicyEngine();

        // Evaluate components against policies
        List<PolicyViolation> violations = pe.evaluate(components);

        if (violations.isEmpty()) {
            LOGGER.info("No policy violations detected for project: " + project.getName());
            dispatchNoViolationNotification(project, components);
        } else {
            LOGGER.info("Policy violations detected for project: " + project.getName());
        }

        // Existing dispatch for metrics
        if (project != null) {
            Event.dispatch(new ProjectMetricsUpdateEvent(project.getUuid()));
        }
    }

    private void dispatchNoViolationNotification(Project project, List<Component> components) {
        try (QueryManager qm = new QueryManager()) {
            // Re-fetch the project to ensure it is fully populated
            Project fullProject = qm.getObjectById(Project.class, project.getId());
            if (fullProject == null) {
                LOGGER.warn("LanceLog Unable to load full project details for project ID: " + project.getId());
                return; // Exit the method if the project cannot be loaded
            }

            String componentNames = components.stream()
                    .map(Component::getName)
                    .filter(name -> name != null && !name.isEmpty())
                    .sorted()
                    .toList()
                    .toString();

            String content = "Policy evaluation for project '" + fullProject.getName() + "' completed.\n"
                    + "No violations were detected for the following components: " + componentNames;

            final NotificationGroup notificationGroup = NotificationGroup.PROJECT_AUDIT_CHANGE;

            Notification noViolationNotification = new Notification()
                    .scope(NotificationScope.PORTFOLIO)
                    .group(notificationGroup)
                    .level(NotificationLevel.INFORMATIONAL)
                    .title("No Policy Violations")
                    .content(content)
                    .subject(fullProject);

            Notification.dispatch(noViolationNotification);
            LOGGER.info("LanceLog Dispatching no-violation notification for project: " + fullProject.getName());
            LOGGER.info("No-violation notification content: " + content);
        } catch (Exception e) {
            LOGGER.error("LanceLog Error dispatching no-violation notification for project: " + project.getId(), e);
        }
    }


}
