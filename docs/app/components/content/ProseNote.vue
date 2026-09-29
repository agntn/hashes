<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <HashesCallout kind="note" :title="title"><slot mdc-unwrap="p" /></HashesCallout>
</template>
