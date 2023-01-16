polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  actions: {
    retrySearch() {
      this.set('message', '');
      this.set('errorMessage', '');
      this.set('isRunning', true);

      this.sendIntegrationMessage({ data: { entity: this.block.entity } })
        .then((data) => {
          this.set('details', data.details);
          this.set('block.data.summary', data.summary);

          if (data.details.apiLimitReached) {
            this.set('message', 'Search limit hit again');
          }
        })
        .catch((err) => {
          console.error(err);
          const errorMsgTitle =
            err.meta && err.meta.detail ? err.meta.detail : 'Unknown Reason';
          this.set('errorMessageTitle', `Failed on Retry: ${errorMsgTitle}`);
          this.set('errorMessageBody', JSON.stringify(err.meta, null, 4));
        })
        .finally(() => {
          this.set('isRunning', false);
        });
    }
  }
});
