import * as component from './component';
import * as registry from '../registry';
import * as storeContainer from '../store/container';
import {
    getAssociatedTriggerIds,
    UPDATE_TRIGGER_TYPES,
} from '../triggers/associatedTriggers';
import { requireRole } from './rbac';
import logger from '../log';
const log = logger.child({ component: 'trigger' });

export function getTriggers(req, res) {
    return component.getAll(req, res, 'trigger');
}

export function getTrigger(req, res) {
    return component.getById(req, res, 'trigger');
}

/**
 * Run a specific trigger on a specific container provided in the payload.
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function runTrigger(req, res) {
    const triggerType = req.params.type;
    const triggerName = req.params.name;
    let containerToTrigger = req.body;

    const triggerToRun =
        registry.getState().trigger[`${triggerType}.${triggerName}`];
    if (!triggerToRun) {
        log.warn(`No trigger found(type=${triggerType}, name=${triggerName})`);
        res.status(404).json({
            error: 'Not found',
            message: `Error when running trigger ${triggerType}.${triggerName} (trigger not found)`,
        });
        return;
    }
    if (!containerToTrigger) {
        log.warn(
            `Trigger cannot be executed without container (type=${triggerType}, name=${triggerName})`,
        );
        res.status(400).json({
            error: 'Bad Request',
            message: `Error when running trigger ${triggerType}.${triggerName} (container is undefined)`,
        });
        return;
    }

    // An update trigger acts on a real container, so it only runs on a stored
    // one it is associated with; notification triggers can be tested with any payload.
    if (UPDATE_TRIGGER_TYPES.includes(triggerType)) {
        const triggerId = `${triggerType}.${triggerName}`;
        const storedContainer = storeContainer.getContainer(
            containerToTrigger.id,
        );
        if (!storedContainer) {
            res.status(404).json({
                error: 'Not found',
                message: `Error when running trigger ${triggerId} (container not found)`,
            });
            return;
        }
        if (!getAssociatedTriggerIds(storedContainer).has(triggerId)) {
            res.status(403).json({
                error: 'Forbidden',
                message: `Trigger ${triggerId} is not associated with container ${storedContainer.name}`,
            });
            return;
        }
        containerToTrigger = storedContainer;
    }

    try {
        await triggerToRun.trigger(containerToTrigger);
        log.info(
            `Trigger executed with success (type=${triggerType}, name=${triggerName}, container=${JSON.stringify(containerToTrigger)})`,
        );
        res.status(200).json({});
    } catch (e) {
        log.warn(
            `Error when running trigger ${triggerType}.${triggerName} (${e.message})`,
        );
        res.status(500).json({
            error: 'Trigger execution failed',
            message: `Error when running trigger ${triggerType}.${triggerName} (${e.message})`,
        });
    }
}

/**
 * Init Router.
 * @returns {*}
 */
export function init() {
    const router = component.init('trigger');
    router.post(
        '/:type/:name',
        requireRole(['admin', 'rw'], 'write'),
        runTrigger,
    );
    return router;
}
