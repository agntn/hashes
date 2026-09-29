<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <HashesCallout kind="tip" :title="title"><slot mdc-unwrap="p" /></HashesCallout>
</template>
