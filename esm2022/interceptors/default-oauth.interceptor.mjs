import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout, } from 'rxjs/operators';
import * as i0 from "@angular/core";
import * as i1 from "../oauth-service.mjs";
import * as i2 from "./resource-server-error-handler.mjs";
import * as i3 from "../oauth-module.config.mjs";
export class DefaultOAuthInterceptor {
    constructor(oAuthService, errorHandler, moduleConfig) {
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    checkUrl(url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find((u) => url.toLowerCase().startsWith(u.toLowerCase()));
        }
        return true;
    }
    intercept(req, next) {
        const url = req.url.toLowerCase();
        if (!this.moduleConfig ||
            !this.moduleConfig.resourceServer ||
            !this.checkUrl(url)) {
            return next.handle(req);
        }
        const sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError((err) => this.errorHandler.handleError(err)));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter((token) => !!token)), this.oAuthService.events.pipe(filter((e) => e.type === 'token_received'), timeout(this.oAuthService.waitForTokenInMsec || 0), catchError(() => of(null)), // timeout is not an error
        map(() => this.oAuthService.getAccessToken()))).pipe(take(1), mergeMap((token) => {
            if (token) {
                const header = 'Bearer ' + token;
                const headers = req.headers.set('Authorization', header);
                req = req.clone({ headers });
            }
            return next
                .handle(req)
                .pipe(catchError((err) => this.errorHandler.handleError(err)));
        }));
    }
    static { this.ɵfac = i0.ɵɵngDeclareFactory({ minVersion: "12.0.0", version: "17.0.6", ngImport: i0, type: DefaultOAuthInterceptor, deps: [{ token: i1.OAuthService }, { token: i2.OAuthResourceServerErrorHandler }, { token: i3.OAuthModuleConfig, optional: true }], target: i0.ɵɵFactoryTarget.Injectable }); }
    static { this.ɵprov = i0.ɵɵngDeclareInjectable({ minVersion: "12.0.0", version: "17.0.6", ngImport: i0, type: DefaultOAuthInterceptor }); }
}
i0.ɵɵngDeclareClassMetadata({ minVersion: "12.0.0", version: "17.0.6", ngImport: i0, type: DefaultOAuthInterceptor, decorators: [{
            type: Injectable
        }], ctorParameters: () => [{ type: i1.OAuthService }, { type: i2.OAuthResourceServerErrorHandler }, { type: i3.OAuthModuleConfig, decorators: [{
                    type: Optional
                }] }] });
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3Byb2plY3RzL2xpYi9zcmMvaW50ZXJjZXB0b3JzL2RlZmF1bHQtb2F1dGguaW50ZXJjZXB0b3IudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUNMLFVBQVUsRUFDVixNQUFNLEVBQ04sR0FBRyxFQUNILElBQUksRUFDSixRQUFRLEVBQ1IsT0FBTyxHQUNSLE1BQU0sZ0JBQWdCLENBQUM7Ozs7O0FBTXhCLE1BQU0sT0FBTyx1QkFBdUI7SUFDbEMsWUFDVSxZQUEwQixFQUMxQixZQUE2QyxFQUNqQyxZQUErQjtRQUYzQyxpQkFBWSxHQUFaLFlBQVksQ0FBYztRQUMxQixpQkFBWSxHQUFaLFlBQVksQ0FBaUM7UUFDakMsaUJBQVksR0FBWixZQUFZLENBQW1CO0lBQ2xELENBQUM7SUFFSSxRQUFRLENBQUMsR0FBVztRQUMxQixJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLG1CQUFtQixFQUFFO1lBQ3hELE9BQU8sSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsbUJBQW1CLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDbEU7UUFFRCxJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLFdBQVcsRUFBRTtZQUNoRCxPQUFPLENBQUMsQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FDL0QsR0FBRyxDQUFDLFdBQVcsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsV0FBVyxFQUFFLENBQUMsQ0FDOUMsQ0FBQztTQUNIO1FBRUQsT0FBTyxJQUFJLENBQUM7SUFDZCxDQUFDO0lBRU0sU0FBUyxDQUNkLEdBQXFCLEVBQ3JCLElBQWlCO1FBRWpCLE1BQU0sR0FBRyxHQUFHLEdBQUcsQ0FBQyxHQUFHLENBQUMsV0FBVyxFQUFFLENBQUM7UUFFbEMsSUFDRSxDQUFDLElBQUksQ0FBQyxZQUFZO1lBQ2xCLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjO1lBQ2pDLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsRUFDbkI7WUFDQSxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDekI7UUFFRCxNQUFNLGVBQWUsR0FBRyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxlQUFlLENBQUM7UUFFekUsSUFBSSxDQUFDLGVBQWUsRUFBRTtZQUNwQixPQUFPLElBQUk7aUJBQ1IsTUFBTSxDQUFDLEdBQUcsQ0FBQztpQkFDWCxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDbEU7UUFFRCxPQUFPLEtBQUssQ0FDVixFQUFFLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxLQUFLLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUN2RSxJQUFJLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQzNCLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyxnQkFBZ0IsQ0FBQyxFQUMxQyxPQUFPLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxrQkFBa0IsSUFBSSxDQUFDLENBQUMsRUFDbEQsVUFBVSxDQUFDLEdBQUcsRUFBRSxDQUFDLEVBQUUsQ0FBQyxJQUFJLENBQUMsQ0FBQyxFQUFFLDBCQUEwQjtRQUN0RCxHQUFHLENBQUMsR0FBRyxFQUFFLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLEVBQUUsQ0FBQyxDQUM5QyxDQUNGLENBQUMsSUFBSSxDQUNKLElBQUksQ0FBQyxDQUFDLENBQUMsRUFDUCxRQUFRLENBQUMsQ0FBQyxLQUFLLEVBQUUsRUFBRTtZQUNqQixJQUFJLEtBQUssRUFBRTtnQkFDVCxNQUFNLE1BQU0sR0FBRyxTQUFTLEdBQUcsS0FBSyxDQUFDO2dCQUNqQyxNQUFNLE9BQU8sR0FBRyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxlQUFlLEVBQUUsTUFBTSxDQUFDLENBQUM7Z0JBQ3pELEdBQUcsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUUsT0FBTyxFQUFFLENBQUMsQ0FBQzthQUM5QjtZQUVELE9BQU8sSUFBSTtpQkFDUixNQUFNLENBQUMsR0FBRyxDQUFDO2lCQUNYLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQyxHQUFHLEVBQUUsRUFBRSxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsV0FBVyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQztRQUNuRSxDQUFDLENBQUMsQ0FDSCxDQUFDO0lBQ0osQ0FBQzs4R0FqRVUsdUJBQXVCO2tIQUF2Qix1QkFBdUI7OzJGQUF2Qix1QkFBdUI7a0JBRG5DLFVBQVU7OzBCQUtOLFFBQVEiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlLCBPcHRpb25hbCB9IGZyb20gJ0Bhbmd1bGFyL2NvcmUnO1xuXG5pbXBvcnQge1xuICBIdHRwRXZlbnQsXG4gIEh0dHBIYW5kbGVyLFxuICBIdHRwSW50ZXJjZXB0b3IsXG4gIEh0dHBSZXF1ZXN0LFxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQgeyBPYnNlcnZhYmxlLCBvZiwgbWVyZ2UgfSBmcm9tICdyeGpzJztcbmltcG9ydCB7XG4gIGNhdGNoRXJyb3IsXG4gIGZpbHRlcixcbiAgbWFwLFxuICB0YWtlLFxuICBtZXJnZU1hcCxcbiAgdGltZW91dCxcbn0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlciB9IGZyb20gJy4vcmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXInO1xuaW1wb3J0IHsgT0F1dGhNb2R1bGVDb25maWcgfSBmcm9tICcuLi9vYXV0aC1tb2R1bGUuY29uZmlnJztcbmltcG9ydCB7IE9BdXRoU2VydmljZSB9IGZyb20gJy4uL29hdXRoLXNlcnZpY2UnO1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgRGVmYXVsdE9BdXRoSW50ZXJjZXB0b3IgaW1wbGVtZW50cyBIdHRwSW50ZXJjZXB0b3Ige1xuICBjb25zdHJ1Y3RvcihcbiAgICBwcml2YXRlIG9BdXRoU2VydmljZTogT0F1dGhTZXJ2aWNlLFxuICAgIHByaXZhdGUgZXJyb3JIYW5kbGVyOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICAgIEBPcHRpb25hbCgpIHByaXZhdGUgbW9kdWxlQ29uZmlnOiBPQXV0aE1vZHVsZUNvbmZpZyxcbiAgKSB7fVxuXG4gIHByaXZhdGUgY2hlY2tVcmwodXJsOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgICBpZiAodGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuY3VzdG9tVXJsVmFsaWRhdGlvbikge1xuICAgICAgcmV0dXJuIHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmN1c3RvbVVybFZhbGlkYXRpb24odXJsKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuYWxsb3dlZFVybHMpIHtcbiAgICAgIHJldHVybiAhIXRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmFsbG93ZWRVcmxzLmZpbmQoKHUpID0+XG4gICAgICAgIHVybC50b0xvd2VyQ2FzZSgpLnN0YXJ0c1dpdGgodS50b0xvd2VyQ2FzZSgpKSxcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBwdWJsaWMgaW50ZXJjZXB0KFxuICAgIHJlcTogSHR0cFJlcXVlc3Q8YW55PixcbiAgICBuZXh0OiBIdHRwSGFuZGxlcixcbiAgKTogT2JzZXJ2YWJsZTxIdHRwRXZlbnQ8YW55Pj4ge1xuICAgIGNvbnN0IHVybCA9IHJlcS51cmwudG9Mb3dlckNhc2UoKTtcblxuICAgIGlmIChcbiAgICAgICF0aGlzLm1vZHVsZUNvbmZpZyB8fFxuICAgICAgIXRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyIHx8XG4gICAgICAhdGhpcy5jaGVja1VybCh1cmwpXG4gICAgKSB7XG4gICAgICByZXR1cm4gbmV4dC5oYW5kbGUocmVxKTtcbiAgICB9XG5cbiAgICBjb25zdCBzZW5kQWNjZXNzVG9rZW4gPSB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5zZW5kQWNjZXNzVG9rZW47XG5cbiAgICBpZiAoIXNlbmRBY2Nlc3NUb2tlbikge1xuICAgICAgcmV0dXJuIG5leHRcbiAgICAgICAgLmhhbmRsZShyZXEpXG4gICAgICAgIC5waXBlKGNhdGNoRXJyb3IoKGVycikgPT4gdGhpcy5lcnJvckhhbmRsZXIuaGFuZGxlRXJyb3IoZXJyKSkpO1xuICAgIH1cblxuICAgIHJldHVybiBtZXJnZShcbiAgICAgIG9mKHRoaXMub0F1dGhTZXJ2aWNlLmdldEFjY2Vzc1Rva2VuKCkpLnBpcGUoZmlsdGVyKCh0b2tlbikgPT4gISF0b2tlbikpLFxuICAgICAgdGhpcy5vQXV0aFNlcnZpY2UuZXZlbnRzLnBpcGUoXG4gICAgICAgIGZpbHRlcigoZSkgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcbiAgICAgICAgdGltZW91dCh0aGlzLm9BdXRoU2VydmljZS53YWl0Rm9yVG9rZW5Jbk1zZWMgfHwgMCksXG4gICAgICAgIGNhdGNoRXJyb3IoKCkgPT4gb2YobnVsbCkpLCAvLyB0aW1lb3V0IGlzIG5vdCBhbiBlcnJvclxuICAgICAgICBtYXAoKCkgPT4gdGhpcy5vQXV0aFNlcnZpY2UuZ2V0QWNjZXNzVG9rZW4oKSksXG4gICAgICApLFxuICAgICkucGlwZShcbiAgICAgIHRha2UoMSksXG4gICAgICBtZXJnZU1hcCgodG9rZW4pID0+IHtcbiAgICAgICAgaWYgKHRva2VuKSB7XG4gICAgICAgICAgY29uc3QgaGVhZGVyID0gJ0JlYXJlciAnICsgdG9rZW47XG4gICAgICAgICAgY29uc3QgaGVhZGVycyA9IHJlcS5oZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsIGhlYWRlcik7XG4gICAgICAgICAgcmVxID0gcmVxLmNsb25lKHsgaGVhZGVycyB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBuZXh0XG4gICAgICAgICAgLmhhbmRsZShyZXEpXG4gICAgICAgICAgLnBpcGUoY2F0Y2hFcnJvcigoZXJyKSA9PiB0aGlzLmVycm9ySGFuZGxlci5oYW5kbGVFcnJvcihlcnIpKSk7XG4gICAgICB9KSxcbiAgICApO1xuICB9XG59XG4iXX0=