const selectAllCommunities = document.getElementById('select-all-cb');

selectAllCommunities?.addEventListener('change', () => {
  window.toggleAllCommunities(!selectAllCommunities.checked);
});
