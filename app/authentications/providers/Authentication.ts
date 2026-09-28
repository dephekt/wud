import Component from '../../registry/Component';
import { Strategy } from 'passport';
import { Express } from 'express';

class Authentication extends Component {
    /**
     * Init the Trigger.
     */
    async init() {
        await this.initAuthentication();
    }

    /**
     * Init Trigger. Can be overridden in trigger implementation class.
     */
    async initAuthentication() {
        // do nothing by default
    }

    /**
     * Return passport strategy.
     */
    getStrategy(_app: Express): Strategy {
        throw new Error('getStrategy must be implemented');
    }

    getStrategyDescription(): StrategyDescription {
        throw new Error('getStrategyDescription must be implemented');
    }

    /**
     * Whether this authentication validates OAuth access tokens sent as API
     * bearer tokens. Can be overridden in authentication implementation class.
     */
    acceptsAccessTokens(): boolean {
        return false;
    }

    /**
     * Resolve the user for an API bearer access token, or undefined when the
     * token is not acceptable.
     */
    async verifyAccessToken(_accessToken: string): Promise<unknown> {
        return undefined;
    }
}

export default Authentication;

export interface StrategyDescription {
    type: string;
    name: string;
    logoutUrl?: string;
}
