<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <HashesCallout kind="caution" :title="title"><slot mdc-unwrap="p" /></HashesCallout>
</template>
