const resolvers = {
  Query: {
    tracks(_, __, { dataSources }) {
      return dataSources.trackAPI.getTracks();
    },
    track(_, { id }, { dataSources }) {
      return dataSources.trackAPI.getTrack(id);
    },
  },
  Track: {
    author({ authorId }, _, { dataSources }) {
      return dataSources.trackAPI.getAuthor(authorId);
    },
  },
};

export default resolvers;
