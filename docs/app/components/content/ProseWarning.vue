<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <HashesCallout kind="warning" :title="title"><slot mdc-unwrap="p" /></HashesCallout>
</template>
