new Vue({
  el: '#app',
  data() {
    return {
      url: '',
      results: [],
    };
  },
  methods: {
    performScan() {
      axios.post('/scan', { url: this.url })
        .then((response) => {
          this.results = response.data.results;
        })
        .catch((error) => {
          console.error(error);
        });
    },
  },
});
